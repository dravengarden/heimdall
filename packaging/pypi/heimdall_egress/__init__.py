import os
from importlib.resources import files
from pathlib import Path
import sys


def native_path() -> Path:
    return Path(str(files("heimdall_egress").joinpath("native", "heimdall")))


def main() -> None:
    binary = native_path()
    arguments = sys.argv[1:]

    if Path(sys.argv[0]).name.startswith("heimdall-egress") and arguments == [
        "--print-native-path"
    ]:
        print(binary)
        return

    try:
        os.execv(binary, [str(binary), *arguments])
    except OSError as error:
        print(f"failed to start {binary}: {error}", file=sys.stderr)
        raise SystemExit(1) from error
