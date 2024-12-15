import argparse
from pathlib import Path


def main(args: list[str] | None = None) -> None:
    cli_args = argparse.ArgumentParser(
        description="Luminaut: Casting light on shadow cloud deployments.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    cli_args.add_argument("--log", type=Path, default="luminaut.log", help="Log file.")
    cli_args.add_argument(
        "--verbose", action="store_true", help="Verbose output in the log file."
    )
    cli_args.add_argument(
        "--config", type=Path, default="luminaut.toml", help="Configuration file."
    )
    args = cli_args.parse_args(args)


if __name__ == "__main__":
    main()
