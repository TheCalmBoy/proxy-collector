import json
import subprocess
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent


def tracked_paths():
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO, check=True, capture_output=True
    )
    return [path.decode("utf-8") for path in result.stdout.split(b"\0") if path]


class CodeMapTests(unittest.TestCase):
    def setUp(self):
        self.mapping = json.loads((REPO / "CODE_MAP.json").read_text(encoding="utf-8"))
        self.serialized = json.dumps(self.mapping)
        self.paths = tracked_paths()

    def test_every_tracked_top_level_directory_is_listed(self):
        directories = {
            path.split("/", 1)[0]
            for path in self.paths
            if "/" in path
        }
        missing = sorted(directory for directory in directories if directory not in self.serialized)
        self.assertEqual(missing, [], f"top-level directories missing from CODE_MAP.json: {missing}")

    def test_every_tracked_tools_python_file_is_listed(self):
        missing = sorted(
            path for path in self.paths
            if path.startswith("tools/") and path.endswith(".py") and path not in self.serialized
        )
        self.assertEqual(missing, [], f"tools Python files missing from CODE_MAP.json: {missing}")


if __name__ == "__main__":
    unittest.main()
