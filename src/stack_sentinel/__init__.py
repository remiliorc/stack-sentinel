"""stack-sentinel: low-noise health watcher for self-hosted container stacks."""

from .anomaly import EwmaDetector
from .collectors import FAIL, OK, WARN, Check, DockerCollector, HttpCollector, SystemdCollector
from .engine import Event, Sentinel

__all__ = ["EwmaDetector", "Check", "OK", "WARN", "FAIL", "DockerCollector",
           "HttpCollector", "SystemdCollector", "Event", "Sentinel"]
__version__ = "0.1.0"
