from abc import ABCMeta, abstractmethod
from typing import Any, Optional

from . import transport


class BaseProvider(metaclass=ABCMeta):
    """
    Base class for credential providers.
    """

    @abstractmethod
    def prepare(self, request: Optional[transport.RequestBase] = None) -> None: ...

    @abstractmethod
    def validate(self, credential: str) -> Any: ...


class AsyncBaseProvider:
    @abstractmethod
    async def prepare(
        self, request: Optional[transport.AsyncRequestBase] = None
    ) -> None: ...  # type: ignore[override]
