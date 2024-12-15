import argparse
import logging
from pathlib import Path

logger = logging.getLogger()
logger.getChild("boto3").setLevel(logging.ERROR)
logger.getChild("botocore").setLevel(logging.ERROR)


def configure_logging(log_file: Path, verbose: bool) -> None:
    # Allow all messages to pass through the root handler.
    logger.setLevel(logging.DEBUG)

    log_format = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    log_file = logging.FileHandler(log_file)
    log_file.setLevel(logging.DEBUG)
    log_file.setFormatter(log_format)

    logger.addHandler(log_file)

    log_console = logging.StreamHandler()
    log_level = logging.DEBUG if verbose else logging.INFO
    log_console.setLevel(log_level)
    log_console.setFormatter(log_format)

    logger.addHandler(log_console)


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
    configure_logging(args.log, args.verbose)
    logger.info("Luminaut started.")
    logger.debug(f"Is verbose? {args.verbose}")


if __name__ == "__main__":
    main()
