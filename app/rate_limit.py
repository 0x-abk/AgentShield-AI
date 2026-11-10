import time
import threading
from collections import defaultdict, deque
from math import ceil


class RateLimiter:
    def __init__(self, max_requests=60, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, client_id):
        now = time.monotonic()

        with self.lock:
            timestamps = self.requests[client_id]
            cutoff = now - self.window_seconds

            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.max_requests:
                retry_after = ceil(
                    self.window_seconds - (now - timestamps[0])
                )
                return False, max(1, retry_after)

            timestamps.append(now)
            return True, 0
