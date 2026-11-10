"""Fail a release build if its retained runtime differs from the lock file."""
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import sys


def verify(path):
    mismatches = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, expected = line.split("==", 1)
        try:
            actual = version(name)
        except PackageNotFoundError:
            actual = "missing"
        if actual != expected:
            mismatches.append(f"{name}: expected {expected}, found {actual}")
    if mismatches:
        raise SystemExit("Runtime differs from lock file:\n" + "\n".join(mismatches))
    print("All retained runtime dependencies match requirements.lock")


if __name__ == "__main__":
    verify(sys.argv[1])
