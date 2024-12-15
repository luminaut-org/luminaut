from dataclasses import dataclass

from perimeter_scanner.query import QueryPublicAwsEni


@dataclass
class LuminautConfig:
    pass


class Luminaut:
    def __init__(self, config: LuminautConfig):
        self.config = config

    def run(self):
        # Step 1: Enumerate ENIs with public IPs
        enis_with_public_ips = QueryPublicAwsEni().run()
        for eni in enis_with_public_ips.data:
            eni.print_to_console()
