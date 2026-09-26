"""Executable oracle using integer division, not P4 shifts."""
from dataclasses import dataclass, asdict

CLOCK_MASK = (1 << 48) - 1


@dataclass
class Port:
    prev_q: int = 0
    trend_q8: int = 0
    last_epoch: int = 0
    state: int = 0
    recovery_count: int = 0
    sample_counter: int = 0
    last_report: int = 0
    initialized: int = 0

    def step(self, q, now, cfg, can_insert=True):
        p, f = cfg["predictor"], cfg["fsm"]
        if not self.initialized:
            self.prev_q, self.last_epoch, self.initialized = q, now, 1
            self.trend_q8 = self.recovery_count = self.state = 0
            self.sample_counter = self.last_report = 0
        dt = (now - self.last_epoch) & CLOCK_MASK
        if dt >= p["epoch_us"]:
            if dt >= f["idle_reset_us"] and q < cfg["queue"]["release_threshold_packets"]:
                self.trend_q8 = self.recovery_count = self.state = 0
                self.prev_q = q
            elif dt > f["gap_reset_multiple"] * p["epoch_us"]:
                self.trend_q8 = 0
                self.prev_q = q
            else:
                divisor = 2 ** p["ewma_alpha_shift"]
                self.trend_q8 = (self.trend_q8 - self.trend_q8 // divisor
                                 + max(q - self.prev_q, 0) * (256 // divisor))
                near = q + p["near_horizon"] * self.trend_q8 // 256
                far = q + p["far_horizon"] * self.trend_q8 // 256
                threshold = cfg["queue"]["event_threshold_packets"]
                target = 2 if q >= threshold or near >= threshold else (1 if far >= threshold else 0)
                if target >= self.state:
                    self.state, self.recovery_count = target, 0
                else:
                    self.recovery_count += 1
                    if self.recovery_count == f["recovery_epochs"]:
                        self.state -= 1
                        self.recovery_count = 0
                self.prev_q = q
            self.last_epoch = now
        period = cfg["sampling"]["watch_mask" if self.state == 1 else "quiet_mask"] + 1
        emit = self.state == 2 or self.sample_counter % period == 0
        reason = (3 if q >= cfg["queue"]["event_threshold_packets"] else 2) if self.state == 2 else self.state
        self.sample_counter = (self.sample_counter + 1) % (1 << 32)
        if not emit and ((now - self.last_report) & CLOCK_MASK) >= cfg["freshness"]["max_silence_us"]:
            emit, reason = True, 4
        if emit and can_insert:
            self.last_report = now
        far = q + p["far_horizon"] * self.trend_q8 // 256
        return emit, reason, min(far, 0x7FFFF)

    def registers(self):
        return asdict(self)
