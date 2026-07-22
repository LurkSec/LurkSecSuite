import time
from collections import defaultdict
from typing import Dict, Any

class RateLimiter:
    """
    Per-IP request rate limiter. Flags IPs exceeding threshold requests per window.
    """
    WINDOW_SECONDS = 60
    THRESHOLD = 100

    def __init__(self):
        self._buckets: Dict[str, list] = defaultdict(list)
        self._blocked: Dict[str, str] = {}

    def record_request(self, ip: str) -> Dict[str, Any]:
        now = time.time()
        window_start = now - self.WINDOW_SECONDS
        self._buckets[ip] = [t for t in self._buckets[ip] if t > window_start]
        self._buckets[ip].append(now)

        count = len(self._buckets[ip])
        exceeded = count >= self.THRESHOLD

        if exceeded and ip not in self._blocked:
            self._blocked[ip] = time.strftime("%Y-%m-%d %H:%M:%S")

        return {
            "ip": ip,
            "request_count": count,
            "window_seconds": self.WINDOW_SECONDS,
            "threshold": self.THRESHOLD,
            "rate_limited": exceeded,
            "blocked_since": self._blocked.get(ip)
        }

    def get_top_ips(self, limit: int = 20) -> list:
        now = time.time()
        window_start = now - self.WINDOW_SECONDS
        results = []
        for ip, times in self._buckets.items():
            valid = [t for t in times if t > window_start]
            if valid:
                results.append({
                    "ip": ip,
                    "request_count": len(valid),
                    "rate_limited": len(valid) >= self.THRESHOLD,
                    "blocked_since": self._blocked.get(ip, None)
                })
        results.sort(key=lambda x: x["request_count"], reverse=True)
        return results[:limit]

    def get_blocked_ips(self) -> list:
        return [{"ip": ip, "blocked_since": ts} for ip, ts in self._blocked.items()]
