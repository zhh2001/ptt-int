// PTT-INT: Egress Pipeline
// Implements per-egress-port predictor, QUIET/WATCH/BURST FSM,
// adaptive sampling, telemetry header insertion, and freshness safeguard.
//
// Constants and types are defined in headers.p4.

control PttEgress(inout headers_t hdr,
                  inout local_metadata_t meta,
                  inout standard_metadata_t stdmeta)
{
    // ================================================================
    // Register Arrays
    //
    // All per-port registers are sized to 512 entries, indexed by
    // standard_metadata.egress_port (9-bit, range 0-511).
    // ================================================================

    // --- Global configuration registers ---
    register<bit<3>>(1)  scheme_mode_reg;   // 0=FULL..6=PTT (see headers.p4)
    register<bit<12>>(1) switch_id_reg;     // this switch's identifier

    // --- Per-port predictor state ---
    register<bit<32>>(512) prev_q_reg;          // q_{k-1}: previous epoch queue depth
    register<bit<32>>(512) trend_q8_reg;        // G_k: Q8 fixed-point one-sided EWMA
    register<bit<48>>(512) last_epoch_reg;      // timestamp of last predictor update (us)
    register<bit<2>>(512)  state_reg;           // QUIET(0) / WATCH(1) / BURST(2)
    register<bit<8>>(512)  recovery_count_reg;  // consecutive lower-target epochs
    register<bit<32>>(512) sample_counter_reg;  // per-packet counter for deterministic sampling
    register<bit<48>>(512) last_report_reg;     // timestamp of last telemetry report (us)
    register<bit<1>>(512)  initialized_reg;     // whether port state has been initialized

    // --- Delta baseline: last reported queue depth (for |q - q_last| >= Delta_Q) ---
    register<bit<32>>(512) delta_last_q_reg;

    // Note: IPv4 header checksum is recomputed by PttComputeChecksum
    // (checksum.p4) AFTER egress processing, so we do NOT compute it
    // here.  The egress control only modifies header fields (totalLen,
    // udp.length, etc.).  This follows the v1model architecture where
    // checksum computation is deferred to the ComputeChecksum control.

    // ================================================================
    // Apply block: executed once per packet in the egress pipeline
    // ================================================================
    apply {
        // ------------------------------------------------------------
        // Early exit for non-IPv4 or non-UDP packets
        // ------------------------------------------------------------
        if (!hdr.ipv4.isValid() || !hdr.udp.isValid()) {
            return;
        }

        // ------------------------------------------------------------
        // Step 1: Read global configuration registers
        // ------------------------------------------------------------
        bit<3>  scheme_mode;
        bit<12> switch_id;
        scheme_mode_reg.read(scheme_mode, 0);
        switch_id_reg.read(switch_id, 0);

        // ------------------------------------------------------------
        // Step 2: Extract per-packet values
        // ------------------------------------------------------------
        bit<9>  eport = stdmeta.egress_port;
        bit<19> q     = stdmeta.deq_qdepth;
        bit<48> now   = stdmeta.egress_global_timestamp;

        // Expand queue depth to 32-bit for safe arithmetic
        bit<32> q32 = (bit<32>)q;

        // ------------------------------------------------------------
        // Step 3: Read per-port state from registers
        // ------------------------------------------------------------
        bit<32> prev_q       = 0;
        bit<32> trend        = 0;
        bit<48> last_epoch   = 0;
        bit<2>  state        = STATE_QUIET;
        bit<8>  recov_count  = 0;
        bit<32> samp_count   = 0;
        bit<48> last_report  = 0;
        bit<1>  init         = 0;
        bit<32> last_q_delta = 0;

        prev_q_reg.read(prev_q, (bit<32>)eport);
        trend_q8_reg.read(trend, (bit<32>)eport);
        last_epoch_reg.read(last_epoch, (bit<32>)eport);
        state_reg.read(state, (bit<32>)eport);
        recovery_count_reg.read(recov_count, (bit<32>)eport);
        sample_counter_reg.read(samp_count, (bit<32>)eport);
        last_report_reg.read(last_report, (bit<32>)eport);
        initialized_reg.read(init, (bit<32>)eport);
        delta_last_q_reg.read(last_q_delta, (bit<32>)eport);

        // ------------------------------------------------------------
        // Step 4: Initialize per-port state on first packet
        // ------------------------------------------------------------
        bit<32> q_pred_near = 0;
        bit<32> q_pred_far  = 0;
        bit<2>  target_state = STATE_QUIET;
        bool    oracle_updated = false;

        if (init == 0) {
            prev_q       = q32;
            trend        = 0;
            state        = STATE_QUIET;
            recov_count  = 0;
            last_epoch   = now;
            init         = 1;
            last_q_delta = q32;
            last_report  = now;
        }

        // ------------------------------------------------------------
        // Step 5: Epoch-based predictor update
        //
        // The predictor is updated only when at least one measurement
        // epoch (EPOCH_US) has elapsed since the last update. This is
        // a packet-driven epoch: the first dequeued packet after the
        // epoch boundary triggers the update.
        // ------------------------------------------------------------
        if (now >= last_epoch + (bit<48>)EPOCH_US) {
            oracle_updated = true;

            // Compute elapsed time since last epoch
            // Safe because the enclosing if guarantees now >= last_epoch + EPOCH_US
            bit<48> elapsed = now - last_epoch;

            // ----- Idle Reset -----
            // Long idleness (> 100 ms) with queue below release threshold:
            // full reset to QUIET, discard all stale trend and state.
            if (elapsed >= (bit<48>)IDLE_RESET_US && q32 < (bit<32>)Q_RELEASE) {
                trend        = 0;
                prev_q       = q32;
                state        = STATE_QUIET;
                recov_count  = 0;
                target_state = STATE_QUIET;
            }
            // ----- Gap Reset -----
            // Moderate observation gap (> 20 ms): reset trend but keep
            // the current FSM state. Prevents long-gap deltas from being
            // misinterpreted as rapid buildup.
            else if (elapsed > (bit<48>)GAP_RESET_US) {
                trend        = 0;
                prev_q       = q32;
                recov_count  = 0;
                target_state = state;
            }
            // ----- Normal Epoch Update -----
            else {
                // One-sided positive queue growth
                //   d_k = max(q_k - q_{k-1}, 0)
                // Only positive growth is tracked; decreases are handled
                // by EWMA natural decay.
                bit<32> delta_q = 0;
                if (q32 > prev_q) {
                    delta_q = q32 - prev_q;
                }

                // Q8 fixed-point EWMA
                //   G_k = (1-alpha)*G_{k-1} + alpha*d_k*256
                //       = G_{k-1} - (G_{k-1}>>2) + (delta_q<<6)
                // where alpha = 1/4 and scale = 256.
                // All intermediate values use 32-bit to avoid wrap.
                bit<32> trend_new = trend
                                  - (trend >> EWMA_ALPHA_SHIFT)
                                  + (delta_q << 6);

                // Near-horizon prediction
                // For H_N = 2: q + 2*g = q + 2*G/256 = q + G/128 = q + (G >> 7)
                q_pred_near = q32 + (trend_new >> 7);

                // Far-horizon prediction
                // For H_F = 8: q + 8*g = q + 8*G/256 = q + G/32 = q + (G >> 5)
                q_pred_far = q32 + (trend_new >> 5);

                // ----- Target State Determination -----
                // BURST if current or near-future queue exceeds event threshold.
                // WATCH if far-future queue exceeds event threshold.
                // QUIET otherwise.
                if (q32 >= (bit<32>)Q_EVENT) {
                    target_state = STATE_BURST;
                } else if (q_pred_near >= (bit<32>)Q_EVENT) {
                    target_state = STATE_BURST;
                } else if (q_pred_far >= (bit<32>)Q_EVENT) {
                    target_state = STATE_WATCH;
                } else {
                    target_state = STATE_QUIET;
                }

                // ----- FSM State Transition -----
                if (target_state > state) {
                    // Upward: immediate
                    state        = target_state;
                    recov_count  = 0;
                } else if (target_state == state) {
                    // Same target: reset hysteresis counter
                    recov_count  = 0;
                } else {
                    // Downward: hysteresis
                    // Require M consecutive lower-target epochs before
                    // moving down one level: BURST -> WATCH -> QUIET.
                    recov_count = recov_count + 1;
                    if (recov_count >= (bit<8>)RECOVERY_EPOCHS) {
                        if (state > STATE_QUIET) {
                            state = state - 1;
                        }
                        recov_count = 0;
                    }
                }

                trend  = trend_new;
                prev_q = q32;
            }

            last_epoch = now;
        } else {
            // Not an epoch boundary: predict using the existing trend
            // (no state change, but predictions are used for oracle consistency)
            q_pred_near = q32 + (trend >> 7);
            q_pred_far  = q32 + (trend >> 5);
            target_state = state;
        }

        // ------------------------------------------------------------
        // Step 6: Oracle Logging
        //
        // Output a machine-parseable oracle line ONLY at epoch updates.
        // All schemes use identical oracle logging for fair comparison.
        // This uses BMv2's log_msg extern for logging to the switch log.
        // ------------------------------------------------------------
        if (oracle_updated) {
            log_msg("PTT_ORACLE sw={} port={} ts={} q={} trend={} qn={} qf={} state={} target={}",
                {(bit<32>)switch_id, (bit<32>)eport, now, q32, trend,
                 q_pred_near, q_pred_far, (bit<32>)state, (bit<32>)target_state});
        }

        // ------------------------------------------------------------
        // Step 7: Increment sample counter (shared by all schemes)
        // ------------------------------------------------------------
        samp_count = samp_count + 1;

        // ------------------------------------------------------------
        // Step 8: Telemetry Sampling Decision
        //
        // Each scheme mode implements a different telemetry policy.
        // All share the same forwarding pipeline, packet format,
        // counter, and oracle instrumentation.
        // ------------------------------------------------------------
        bool   emit   = false;
        bit<3> reason = REASON_PERIODIC_QUIET;

        if (scheme_mode == SCHEME_FULL) {
            // B0: FULL-INT — instrument every packet
            emit   = true;
            reason = REASON_BASELINE_TRIGGER;
        }
        else if (scheme_mode == SCHEME_PERIODIC_4) {
            // B1: PERIODIC 1/4
            emit   = ((samp_count & 0x03) == 0);
            reason = REASON_PERIODIC_WATCH;
        }
        else if (scheme_mode == SCHEME_PERIODIC_16) {
            // B1: PERIODIC 1/16
            emit   = ((samp_count & 0x0f) == 0);
            reason = REASON_PERIODIC_WATCH;
        }
        else if (scheme_mode == SCHEME_PERIODIC_32) {
            // B1: PERIODIC 1/32
            emit   = ((samp_count & QUIET_MASK) == 0);
            reason = REASON_PERIODIC_QUIET;
        }
        else if (scheme_mode == SCHEME_REACTIVE) {
            // B2: REACTIVE-INT
            // Full resolution above threshold, background 1/32 otherwise
            if (q32 >= (bit<32>)Q_EVENT) {
                emit   = true;
                reason = REASON_EMERGENCY_THRESHOLD;
            } else {
                emit   = ((samp_count & QUIET_MASK) == 0);
                reason = REASON_PERIODIC_QUIET;
            }
        }
        else if (scheme_mode == SCHEME_DELTA) {
            // B3: DELTA-TRIGGER
            // Emit when |q - q_last_report| >= Delta_Q
            bit<32> q_diff;
            if (q32 > last_q_delta) {
                q_diff = q32 - last_q_delta;
            } else {
                q_diff = last_q_delta - q32;
            }
            if (q_diff >= (bit<32>)DELTA_THRESHOLD) {
                emit          = true;
                reason        = REASON_BASELINE_TRIGGER;
            } else {
                // Background periodic sampling for visibility
                emit   = ((samp_count & QUIET_MASK) == 0);
                reason = REASON_PERIODIC_QUIET;
            }
        }
        else {
            // B4: PTT-INT (default for SCHEME_PTT = 6 and any unknown value)
            // Adaptive sampling based on FSM state
            if (state == STATE_BURST) {
                // High-resolution: every packet
                emit = true;
                if (q32 >= (bit<32>)Q_EVENT) {
                    reason = REASON_EMERGENCY_THRESHOLD;
                } else {
                    reason = REASON_PREDICTIVE_NEAR;
                }
            } else if (state == STATE_WATCH) {
                // Medium resolution: 1/4
                emit   = ((samp_count & WATCH_MASK) == 0);
                reason = REASON_PERIODIC_WATCH;
            } else {
                // Background visibility: 1/32
                emit   = ((samp_count & QUIET_MASK) == 0);
                reason = REASON_PERIODIC_QUIET;
            }
        }

        // ------------------------------------------------------------
        // Step 9: Freshness Safeguard
        //
        // Force a telemetry report if no report has been emitted for
        // longer than MAX_SILENCE_US. Prevents telemetry silence
        // during extended QUIET periods.
        //
        // This runs AFTER the scheme decision so that freshness always
        // takes priority (reason is set to FRESHNESS).
        // ------------------------------------------------------------
        if (now >= last_report + (bit<48>)MAX_SILENCE_US) {
            emit   = true;
            reason = REASON_FRESHNESS;
        }

        // ------------------------------------------------------------
        // Step 10: Update delta baseline reference on every report
        //
        // For the DELTA scheme, any telemetry report (delta-triggered,
        // periodic background, or freshness-forced) updates the
        // reference queue depth for subsequent delta comparisons.
        // ------------------------------------------------------------
        if (emit && scheme_mode == SCHEME_DELTA) {
            last_q_delta = q32;
        }

        // ------------------------------------------------------------
        // Step 11: Write back per-port state registers
        //
        // All state is persisted BEFORE header manipulation so that
        // the next packet sees the updated predictor state regardless
        // of whether header insertion succeeds.
        // ------------------------------------------------------------
        prev_q_reg.write((bit<32>)eport, prev_q);
        trend_q8_reg.write((bit<32>)eport, trend);
        last_epoch_reg.write((bit<32>)eport, last_epoch);
        state_reg.write((bit<32>)eport, state);
        recovery_count_reg.write((bit<32>)eport, recov_count);
        sample_counter_reg.write((bit<32>)eport, samp_count);
        delta_last_q_reg.write((bit<32>)eport, last_q_delta);

        // last_report is only updated when we actually emit
        if (emit) {
            last_report_reg.write((bit<32>)eport, now);
        }

        initialized_reg.write((bit<32>)eport, init);

        // ------------------------------------------------------------
        // Step 12: Populate metadata for deparser / downstream stages
        // ------------------------------------------------------------
        meta.emit_telemetry   = emit;
        meta.emit_reason      = reason;
        meta.current_state    = state;
        meta.qdepth_val       = q;
        meta.q_pred_far_val   = q_pred_far[QDEPTH_WIDTH-1:0];
        meta.timestamp_low_val = now[31:0];

        // Track original UDP destination port for first-insertion
        meta.original_dport = hdr.udp.dstPort;

        // ------------------------------------------------------------
        // Step 13: Telemetry Header Insertion
        //
        // Two phases:
        //   1. If this is the first insertion: create PTT shim (8B)
        //   2. Append hop record (12B) via push_front
        //
        // IPv4 checksum recomputation is deferred to PttComputeChecksum.
        //
        // Use push_front(1) so the most recent (collector-nearest)
        // switch hop is always at index 0.
        // ------------------------------------------------------------
        if (emit) {
            // ----- Phase 1: First insertion -----
            if (!hdr.ptt_shim.isValid()) {
                // Create PTT shim (8 bytes)
                hdr.ptt_shim.setValid();
                hdr.ptt_shim.magic              = PTT_MAGIC;
                hdr.ptt_shim.version            = PTT_VERSION;
                hdr.ptt_shim.flags              = 0;
                hdr.ptt_shim.hop_count          = 0;
                hdr.ptt_shim.original_udp_dport = hdr.udp.dstPort;
                hdr.ptt_shim.reserved           = 0;

                // Change UDP destination port to INT_PORT,
                // save the original dport, and zero UDP checksum
                // so intermediate routers don't reject the packet
                // after payload/header modification.
                meta.original_dport = hdr.udp.dstPort;
                hdr.udp.dstPort     = INT_PORT;
                hdr.udp.checksum    = 0;

                // Add shim size (8 bytes) to UDP length and IP total length
                hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
                hdr.udp.length    = hdr.udp.length + 8;
            }

            // ----- Phase 2: Append local hop record -----
            if (hdr.ptt_shim.hop_count < (bit<8>)MAX_HOPS) {
                // push_front(1): shift existing hops right by one position,
                // making room at index 0 for the new (collector-nearest) hop.
                hdr.hops.push_front(1);

                // Populate hop record (12 bytes)
                hdr.hops[0].setValid();
                hdr.hops[0].switch_id     = switch_id;
                hdr.hops[0].egress_port   = eport;
                hdr.hops[0].state         = state;
                hdr.hops[0].reason        = reason;
                hdr.hops[0].qdepth        = q;
                hdr.hops[0].q_pred_far    = q_pred_far[QPRED_WIDTH-1:0];
                hdr.hops[0].timestamp_low = now[31:0];

                hdr.ptt_shim.hop_count = hdr.ptt_shim.hop_count + 1;

                // Add hop record size (12 bytes) to lengths
                hdr.ipv4.totalLen = hdr.ipv4.totalLen + 12;
                hdr.udp.length    = hdr.udp.length + 12;
            } else {
                // Header stack full: set overflow flag
                // Do NOT append beyond MAX_HOPS; just flag and forward.
                hdr.ptt_shim.flags = hdr.ptt_shim.flags | 0x1;
            }
        }

        // ------------------------------------------------------------
        // Note: IPv4 header checksum recomputation is handled by
        // PttComputeChecksum (checksum.p4) after egress processing.
        // See v1model architecture: ComputeChecksum runs after Egress.
        // ------------------------------------------------------------
    }
}
