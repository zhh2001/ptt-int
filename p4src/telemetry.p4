// Explicit observation inputs permit testing this same
// control with deterministic queue/timestamp traces in a separate P4 program.
control PttTelemetry(inout headers_t hdr, in bit<9> eport,
                     in bit<19> q, in bit<48> now) {
    register<bit<12>>(1) switch_id_reg;
    // Exactly the eight per-port registers and widths.
    register<bit<32>>(512) prev_q_reg;
    register<bit<32>>(512) trend_q8_reg;
    register<bit<48>>(512) last_epoch_reg;
    register<bit<2>>(512) state_reg;
    register<bit<8>>(512) recovery_count_reg;
    register<bit<32>>(512) sample_counter_reg;
    register<bit<48>>(512) last_report_reg;
    register<bit<1>>(512) initialized_reg;

    apply {
        if (hdr.ipv4.isValid() && hdr.udp.isValid()) {
            bit<32> port = (bit<32>)eport;
            bit<32> q32 = (bit<32>)q;
            bit<12> switch_id;
            bit<32> prev_q;
            bit<32> trend;
            bit<48> last_epoch;
            bit<2> state;
            bit<8> recovery;
            bit<32> sample_count;
            bit<48> last_report;
            bit<1> initialized;
            bit<32> near_q;
            bit<32> far_q;
            bit<2> target;
            bit<48> elapsed;
            bool emit;
            bit<3> reason;
            bit<16> extra;
            switch_id_reg.read(switch_id, 0);

            // Serialize the per-port read/modify/write transaction.
            @atomic {
                prev_q_reg.read(prev_q, port);
                trend_q8_reg.read(trend, port);
                last_epoch_reg.read(last_epoch, port);
                state_reg.read(state, port);
                recovery_count_reg.read(recovery, port);
                sample_counter_reg.read(sample_count, port);
                last_report_reg.read(last_report, port);
                initialized_reg.read(initialized, port);
                if (initialized == 0) {
                    prev_q = q32;
                    trend = 0;
                    recovery = 0;
                    state = STATE_QUIET;
                    sample_count = 0;
                    last_report = 0;
                    last_epoch = now;
                    initialized = 1;
                }
                // Modular subtraction also works across the 48-bit clock wrap.
                elapsed = now - last_epoch;
                if (elapsed >= EPOCH_US) {
                    if (elapsed >= IDLE_RESET_US && q32 < Q_RELEASE) {
                        trend = 0;
                        recovery = 0;
                        state = STATE_QUIET;
                        prev_q = q32;
                    } else if (elapsed > GAP_RESET_US) {
                        // retain state AND recovery.
                        trend = 0;
                        prev_q = q32;
                    } else {
                        bit<32> delta = 0;
                        if (q32 > prev_q) { delta = q32 - prev_q; }
                        trend = trend - (trend >> EWMA_ALPHA_SHIFT)
                                      + (delta << EWMA_DELTA_SHIFT);
                        near_q = q32 + (trend >> NEAR_SHIFT);
                        far_q = q32 + (trend >> FAR_SHIFT);
                        if (q32 >= Q_EVENT || near_q >= Q_EVENT) {
                            target = STATE_BURST;
                        } else if (far_q >= Q_EVENT) {
                            target = STATE_WATCH;
                        } else {
                            target = STATE_QUIET;
                        }
                        if (target > state) {
                            state = target;
                            recovery = 0;
                        } else if (target < state) {
                            recovery = recovery + 1;
                            if (recovery >= RECOVERY_EPOCHS) {
                                state = state - 1;
                                recovery = 0;
                            }
                        } else {
                            recovery = 0;
                        }
                        prev_q = q32;
                    }
                    last_epoch = now;
                }
                // Current projection even between epochs or on reset.
                // Only normal epochs above change the committed FSM state.
                far_q = q32 + (trend >> FAR_SHIFT);
                if (state == STATE_BURST) {
                    emit = true;
                    reason = q32 >= Q_EVENT ? (bit<3>)REASON_EMERGENCY_THRESHOLD
                                            : (bit<3>)REASON_PREDICTIVE_NEAR;
                } else if (state == STATE_WATCH) {
                    emit = (sample_count & (bit<32>)WATCH_MASK) == 0;
                    reason = REASON_PERIODIC_WATCH;
                } else {
                    emit = (sample_count & (bit<32>)QUIET_MASK) == 0;
                    reason = REASON_PERIODIC_QUIET;
                }
                // Select BEFORE incrementing.
                sample_count = sample_count + 1;
                elapsed = now - last_report;
                if (!emit && elapsed >= MAX_SILENCE_US) {
                    emit = true;
                    reason = REASON_FRESHNESS;
                }
                if (emit) {
                    if (hdr.ptt_shim.isValid() && hdr.ptt_shim.hop_count == MAX_HOPS) {
                        hdr.ptt_shim.flags = hdr.ptt_shim.flags | 1;
                        hdr.udp.checksum = 0;
                    } else {
                        extra = hdr.ptt_shim.isValid() ? (bit<16>)12 : (bit<16>)20;
                        // No partial insertion or 16-bit length wrap.
                        if (hdr.ipv4.totalLen <= (bit<16>)65535 - extra &&
                            hdr.udp.length <= (bit<16>)65535 - extra) {
                            if (!hdr.ptt_shim.isValid()) {
                                hdr.ptt_shim.setValid();
                                hdr.ptt_shim.magic = PTT_MAGIC;
                                hdr.ptt_shim.version = PTT_VERSION;
                                hdr.ptt_shim.flags = 0;
                                hdr.ptt_shim.hop_count = 0;
                                hdr.ptt_shim.original_udp_dport = hdr.udp.dstPort;
                                hdr.ptt_shim.reserved = 0;
                                hdr.udp.dstPort = INT_PORT;
                            }
                            hdr.hops.push_front(1);
                            // push_front invalidates the new slot.
                            hdr.hops[0].setValid();
                            hdr.hops[0].switch_id = switch_id;
                            hdr.hops[0].egress_port = eport;
                            hdr.hops[0].state = state;
                            hdr.hops[0].reason = reason;
                            hdr.hops[0].qdepth = q;
                            hdr.hops[0].q_pred_far = far_q > 0x7ffff
                                ? (bit<19>)0x7ffff : (bit<19>)far_q;
                            hdr.hops[0].timestamp_low = now[31:0];
                            hdr.ptt_shim.hop_count = hdr.ptt_shim.hop_count + 1;
                            hdr.ipv4.totalLen = hdr.ipv4.totalLen + extra;
                            hdr.udp.length = hdr.udp.length + extra;
                            hdr.udp.checksum = 0;
                            // Actual insertion only.
                            last_report = now;
                        }
                    }
                }
                prev_q_reg.write(port, prev_q);
                trend_q8_reg.write(port, trend);
                last_epoch_reg.write(port, last_epoch);
                state_reg.write(port, state);
                recovery_count_reg.write(port, recovery);
                sample_counter_reg.write(port, sample_count);
                last_report_reg.write(port, last_report);
                initialized_reg.write(port, initialized);
            }
        }
    }
}
