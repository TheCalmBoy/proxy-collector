#!/usr/bin/env python3
"""Run the collector's tests without a container or a package install.

`python -m unittest tests.test_foo` does not work here: tests/ has no
__init__.py, and a bare `tools` package name collides with other things on
the path. Loading each test file by path avoids both, and keeps the local
run identical to what CI executes.

Usage:  python3 run_tests.py [name-fragment ...]
"""
import importlib.util
import pathlib
import sys
import unittest

REPO = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))

TEST_DIR = REPO / "tests"


def load_module(path: pathlib.Path) -> unittest.TestSuite:
    loader = unittest.TestLoader()
    suite = loader.discover(
        str(TEST_DIR), pattern=path.name, top_level_dir=str(REPO)
    )
    return suite


def main() -> int:
    wanted = sys.argv[1:]
    files = sorted(TEST_DIR.glob("test_*.py"))
    if wanted:
        files = [f for f in files if any(w in f.name for w in wanted)]

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    skipped = []
    for path in files:
        # Import the module by path so a test file that shadows a stdlib
        # name cannot win, and so sys.path does not need the repo as a
        # package. A module whose imports are unavailable is reported and
        # skipped rather than aborting the whole run: some tests need
        # third-party packages that only CI installs.
        spec = importlib.util.spec_from_file_location(f"_t_{path.stem}", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        except ModuleNotFoundError as exc:
            skipped.append(f"{path.name} (needs {exc.name})")
            continue
        suite.addTests(loader.loadTestsFromModule(module))

    for note in skipped:
        print(f"SKIP {note}", file=sys.stderr)
    if not wanted:
        print(f"running {len(files) - len(skipped)} test modules")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
