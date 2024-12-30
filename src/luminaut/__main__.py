import argparse
import logging
from pathlib import Path

from luminaut import Luminaut, __version__, models

logger = logging.getLogger()
logger.getChild("boto3").setLevel(logging.ERROR)
logger.getChild("botocore").setLevel(logging.ERROR)
logger.getChild("urllib3.connectionpool").setLevel(logging.ERROR)


luminaut_art = r"""
          _..._
        .'     '.
       /    .-""-\
     .-|   /:.   |
     |  \  |:.   /.-'-.
     | .-'-;:__.'    =/
     .'=  *=|     _.='
    /   _.  |    ;
   ;-.-'|    \   |
  /   | \    _\  _\
  \__/'._;.  ==' ==\
           \    \   |
           /    /   /
           /-._/-._/
           \   `\  \
            `-._/._/
"""


def configure_logging(log_file: Path, verbose: bool) -> None:
    # Allow all messages to pass through the root handler.
    logger.setLevel(logging.DEBUG)

    file_log_format = logging.Formatter(
        "%(asctime)s\t%(levelname)s\t%(name)s\t%(message)s"
    )
    log_file = logging.FileHandler(log_file)
    log_file.setLevel(logging.DEBUG)
    log_file.setFormatter(file_log_format)

    logger.addHandler(log_file)

    console_log_format = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)-24s %(message)s"
    )
    log_console = logging.StreamHandler()
    log_level = logging.DEBUG if verbose else logging.INFO
    log_console.setLevel(log_level)
    log_console.setFormatter(console_log_format)

    logger.addHandler(log_console)


class ArgparseFormatter(
    argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter
):
    pass


def configure_cli_args(args: list[str] | None = None) -> argparse.Namespace:
    cli_args = argparse.ArgumentParser(
        description=f"Luminaut: Casting light on shadow cloud deployments. {luminaut_art}",
        formatter_class=ArgparseFormatter,
    )
    cli_args.add_argument(
        "-c", "--config", type=Path, default=None, help="Configuration file."
    )
    cli_args.add_argument("--log", type=Path, default="luminaut.log", help="Log file.")
    cli_args.add_argument(
        "--verbose", action="store_true", help="Verbose output in the log file."
    )
    cli_args.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return cli_args.parse_args(args)


def load_config(config_file: Path) -> models.LuminautConfig:
    with config_file.open("rb") as f:
        return models.LuminautConfig.from_toml(f)


def main(args: list[str] | None = None) -> None:
    args = configure_cli_args(args)
    configure_logging(args.log, args.verbose)
    config = models.LuminautConfig()
    if args.config and args.config.exists():
        config = load_config(args.config)
    luminaut = Luminaut(config)
    luminaut.run()


if __name__ == "__main__":
    main()
