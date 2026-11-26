"""Streaming anomaly detection with an exponentially weighted mean and variance.

For each metric x_t:
    mean_t = mean_{t-1} + alpha * (x_t - mean_{t-1})
    var_t  = (1 - alpha) * (var_{t-1} + alpha * (x_t - mean_{t-1})^2)
A sample is anomalous when |x_t - mean_{t-1}| / std_{t-1} > z, after a warm-up.
Anomalous samples are only partly absorbed, so a spike does not inflate
the baseline it is judged against.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass
class _State:
    n: int = 0
    mean: float = 0.0
    var: float = 0.0


class EwmaDetector:
    def __init__(self, alpha: float = 0.1, z: float = 4.0, warmup: int = 20,
                 min_std: float = 1e-6, spike_weight: float = 0.1):
        if not 0 < alpha <= 1:
            raise ValueError("alpha must be in (0, 1]")
        self.alpha, self.z, self.warmup = alpha, z, warmup
        self.min_std, self.spike_weight = min_std, spike_weight
        self._s: dict[str, _State] = {}

    def update(self, key: str, x: float) -> float | None:
        """Feed one sample. Returns its z-score if anomalous, otherwise None."""
        s = self._s.setdefault(key, _State())
        if s.n == 0:
            s.n, s.mean = 1, float(x)
            return None
        std = max(math.sqrt(s.var), self.min_std)
        score = abs(x - s.mean) / std
        anomalous = s.n >= self.warmup and score > self.z
        a = self.alpha * (self.spike_weight if anomalous else 1.0)
        d = x - s.mean
        s.mean += a * d
        s.var = (1 - a) * (s.var + a * d * d)
        s.n += 1
        return round(score, 2) if anomalous else None
