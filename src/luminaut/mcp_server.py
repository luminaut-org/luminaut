import logging
from mcp.server.fastmcp import FastMCP

from luminaut.tools.aws import Aws

logger = logging.getLogger('luminaut_mcp')
console_log_format = logging.Formatter(
    "%(asctime)s %(levelname)-8s %(name)-24s %(message)s"
)
log_console = logging.StreamHandler()
log_level = logging.INFO
log_console.setLevel(log_level)
log_console.setFormatter(console_log_format)
logger.addHandler(log_console)

mcp = FastMCP("luminaut")


@mcp.tool()
async def explore_region(region_name: str) -> str:
    """Explore the region of an AWS account to fetch perimeter information.

    This enumerates ENIs with a public IP address, looks for associated EC2 instances, security groups, etc.

    :param region_name: AWS region to fetch perimeter information. Uses format `us-east-1`

    Returns:
        str: String containing the perimeter information in a human-readable format

    """
    aws = Aws()
    scan_results = aws.explore_region(region_name)
    result = ''
    for scan_result in scan_results:
        title, rich_text = scan_result.build_rich_panel()
        result += f"\n{'='*80}\n{title}\n{'='*80}\n{rich_text}\n"
    return result


def main():
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
