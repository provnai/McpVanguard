"""
core/telemetry.py
Performance telemetry for McpVanguard.
Tracks latency metrics and status counts for real-time scale analysis.
"""

import time
import logging
import statistics
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List

logger = logging.getLogger("vanguard.telemetry")

@dataclass
class LayerMetrics:
    latencies: deque = field(default_factory=lambda: deque(maxlen=1000))
    total_calls: int = 0
    errors: int = 0

class Telemetry:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Telemetry, cls).__new__(cls)
            cls._instance._init_metrics()
        return cls._instance

    def _init_metrics(self):
        self.start_time = time.time()
        self.layers: Dict[str, LayerMetrics] = {
            "L1": LayerMetrics(),
            "L2": LayerMetrics(),
            "L3": LayerMetrics(),
            "TOTAL": LayerMetrics(),
        }
        self.counts = {
            "allowed": 0,
            "blocked": 0,
            "warned": 0,
            "error_fail_closed": 0,
        }

    def record_latency(self, layer: str, duration_ms: float):
        if layer in self.layers:
            self.layers[layer].latencies.append(duration_ms)
            self.layers[layer].total_calls += 1

    def record_status(self, status: str):
        if status in self.counts:
            self.counts[status] += 1

    def record_error(self, layer: str):
        if layer in self.layers:
            self.layers[layer].errors += 1

    def get_stats(self) -> Dict:
        now = time.time()
        uptime = now - self.start_time
        
        stats = {
            "uptime_seconds": round(uptime, 2),
            "counts": self.counts,
            "layers": {}
        }
        
        for name, metrics in self.layers.items():
            lats = list(metrics.latencies)
            avg = round(statistics.mean(lats), 3) if lats else 0
            p99 = round(sorted(lats)[int(len(lats) * 0.99)], 3) if len(lats) >= 100 else (max(lats) if lats else 0)
            
            stats["layers"][name] = {
                "avg_ms": avg,
                "p99_ms": p99,
                "total_calls": metrics.total_calls,
                "errors": metrics.errors
            }
            
        return stats

# Global Singleton
metrics = Telemetry()
