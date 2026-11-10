import time
import threading
from collections import defaultdict, deque
from math import ceil


class RateLimiter:
    def __init__(
        self,
        max_requests=60,
        window_seconds=60,
        cleanup_interval=60
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.cleanup_interval = cleanup_interval
        self.requests = defaultdict(deque)
        self.lock = threading.Lock()
        self.last_cleanup = 0

    def _cleanup(self, now):
        if now - self.last_cleanup < self.cleanup_interval:
            return

        cutoff = now - self.window_seconds

        for client_id, timestamps in list(self.requests.items()):
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if not timestamps:
                del self.requests[client_id]

        self.last_cleanup = now

    def allow(self, client_id):
        now = time.monotonic()

        with self.lock:
            self._cleanup(now)

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
