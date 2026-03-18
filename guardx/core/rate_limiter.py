"""
GuardX Rate Limiter Module
Controls request rate per domain using token bucket algorithm.
"""

import asyncio
import time
from collections import defaultdict
from typing import Dict


class RateLimiter:
    """Controls request rate per domain using token bucket algorithm.

    Prevents overwhelming target servers during scans.
    """

    def __init__(self, requests_per_second: float = 10, burst: int = 20):
        """Initialize rate limiter.

        Args:
            requests_per_second: Default rate limit per domain
            burst: Maximum burst size (tokens in bucket)
        """
        self.default_rps = requests_per_second
        self.burst = burst

        # Per-domain token buckets: {domain: {tokens, last_refill_time}}
        self.buckets: Dict[str, Dict] = defaultdict(self._create_bucket)

    def _create_bucket(self) -> dict:
        """Create a new token bucket for a domain."""
        return {
            'tokens': float(self.burst),
            'last_refill': time.time(),
            'rps': self.default_rps,
            'request_count': 0
        }

    async def acquire(self, domain: str) -> None:
        """Wait until a request token is available for the domain.

        Args:
            domain: Target domain for the request
        """
        while True:
            bucket = self.buckets[domain]
            now = time.time()

            # Refill tokens based on time elapsed
            time_passed = now - bucket['last_refill']
            new_tokens = time_passed * bucket['rps']
            bucket['tokens'] = min(bucket['burst'], bucket['tokens'] + new_tokens)
            bucket['last_refill'] = now

            # Check if token available
            if bucket['tokens'] >= 1:
                bucket['tokens'] -= 1
                bucket['request_count'] += 1
                return

            # Wait before checking again
            wait_time = (1 - bucket['tokens']) / bucket['rps']
            await asyncio.sleep(min(wait_time, 0.1))

    def set_rate(self, domain: str, rps: float) -> None:
        """Set custom rate limit for a domain.

        Args:
            domain: Target domain
            rps: Requests per second for this domain
        """
        bucket = self.buckets[domain]
        bucket['rps'] = max(0.1, rps)  # Minimum 0.1 RPS

    def get_stats(self) -> dict:
        """Get current statistics for all domains.

        Returns:
            Dictionary with request counts per domain
        """
        return {
            domain: bucket['request_count']
            for domain, bucket in self.buckets.items()
        }

    def reset_domain(self, domain: str) -> None:
        """Reset counters for a domain.

        Args:
            domain: Target domain
        """
        if domain in self.buckets:
            self.buckets[domain] = self._create_bucket()

    def reset_all(self) -> None:
        """Reset all counters and buckets."""
        self.buckets.clear()


# Global singleton instance
_limiter = None


def get_limiter(requests_per_second: float = 10, burst: int = 20) -> RateLimiter:
    """Get or create global rate limiter instance.

    Args:
        requests_per_second: Default rate limit
        burst: Maximum burst size

    Returns:
        RateLimiter instance
    """
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter(requests_per_second, burst)
    return _limiter
