from __future__ import annotations

from pathlib import Path

from .validation import validate_repository_artifacts


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Validate Sovereign IDE repository artifacts.",
    )
    parser.add_argument("--workspace-root", default=str(Path.cwd()))
    args = parser.parse_args()
    validate_repository_artifacts(args.workspace_root)
    print("Repository artifacts validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
