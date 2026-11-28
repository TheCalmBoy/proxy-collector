import unittest

from tools.source_retries import SOURCE_RETRY_AFTER_MAX_SECONDS, source_retry_policy


class SourceRetryAfterCapTests(unittest.TestCase):
    def test_retry_after_header_is_capped(self):
        retry = source_retry_policy()

        self.assertTrue(retry.respect_retry_after_header)
        self.assertEqual(retry.retry_after_max, SOURCE_RETRY_AFTER_MAX_SECONDS)
        self.assertEqual(retry.parse_retry_after("86400"), SOURCE_RETRY_AFTER_MAX_SECONDS)


if __name__ == "__main__":
    unittest.main()
