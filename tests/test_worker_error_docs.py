import re
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
WORKER = REPO / "workers/proxy-chain-subscription/index.js"
ERROR_DOC = REPO / "docs/errors.md"


class WorkerErrorDocumentationTests(unittest.TestCase):
    def test_every_worker_error_code_is_in_the_table(self):
        source = WORKER.read_text(encoding="utf-8")
        documented = ERROR_DOC.read_text(encoding="utf-8")
        # Include every literal argument in fail(...), including both branches
        # of calls such as fail(condition ? "code_a" : "code_b").
        fail_arguments = re.findall(r"\bfail\((.*?)\)", source, re.DOTALL)
        codes = {
            code
            for arguments in fail_arguments
            for code in re.findall(r'["\']([a-z0-9_]+)["\']', arguments)
        }
        # decodeEntries and parseEntry pass caught Error.message values to
        # fail(...), so include those stable codes as well as literal calls.
        codes.update(re.findall(r'throw new Error\(\s*["\']([a-z0-9_]+)["\']', source))
        table_codes = set(re.findall(r"^\| `([a-z0-9_]+)` \|", documented, re.MULTILINE))
        self.assertTrue(codes, "no Worker error codes were discovered")
        missing = sorted(codes - table_codes)
        self.assertEqual(missing, [], f"Worker error codes missing from docs/errors.md: {missing}")


if __name__ == "__main__":
    unittest.main()
