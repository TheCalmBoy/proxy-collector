"""Bounded retry policy for the pipeline's idempotent source GETs."""

from urllib3.util.retry import Retry

SOURCE_RETRY_AFTER_MAX_SECONDS = 60


def source_retry_policy() -> Retry:
    """Retry transient source failures without honoring unbounded delays."""
    return Retry(
        total=3,
        connect=3,
        read=2,
        status=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        respect_retry_after_header=True,
        retry_after_max=SOURCE_RETRY_AFTER_MAX_SECONDS,
    )
