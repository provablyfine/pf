# Re-export public API
from .recorder import PtyRecorder
from .scenarios import QUICK_TOUR, THOROUGH_TOUR, run_scenario

__all__ = ["QUICK_TOUR", "THOROUGH_TOUR", "PtyRecorder", "run_scenario"]
