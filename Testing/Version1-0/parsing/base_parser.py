from abc import ABC, abstractmethod
from typing import Iterable
from .schema import WebLogEvent


class BaseLogParser(ABC):

    @abstractmethod
    def parse(self, filepath: str) -> Iterable[WebLogEvent]:
        pass
