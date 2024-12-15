from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from perimeter_scanner.enumerate_eni import ENI, AwsEni


@dataclass
class QueryResult:
    source: str
    data: list[AwsEni | dict[str, Any]]


class Query(ABC):
    @abstractmethod
    def run(self, **kwargs) -> QueryResult:
        pass


class QueryPublicAwsEni(Query):
    def __init__(self):
        self.eni = ENI()

    def run(self, **kwargs) -> QueryResult:
        data = []
        for eni in self.eni.fetch_enis_with_public_ips():
            data.append(eni)
        return QueryResult(source="Public AWS ENI", data=data)
