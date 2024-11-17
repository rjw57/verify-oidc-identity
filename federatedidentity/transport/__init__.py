import dataclasses
from abc import ABCMeta, abstractmethod
from typing import Mapping, Optional


@dataclasses.dataclass
class Response:
    content: bytes
    status_code: int
    headers: Mapping[str, str]


class RequestBase(metaclass=ABCMeta):
    """
    Abstract base class for synchronous HTTP transports.
    """

    @abstractmethod
    def __call__(
        self,
        url: str,
        body: Optional[bytes] = None,
        method: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Response:
        """
        Perform a HTTP request.

        Args:
            url: URL of resource to request.
            body: Body of request. Defaults to an empty body.
            method: HTTP method for request. Defaults to 'GET'.
            headers: Map of headers to set on the request. Defaults to an empty mapping.

        Returns:
            The response from the resource server.

        Raises:
            TransportError: on any transport error such as DNS resolution failure. Note that error
                status codes from the server do not raise.
        """


class AsyncRequestBase(metaclass=ABCMeta):
    """
    Abstract base class for asynchronous HTTP transports.
    """

    @abstractmethod
    async def __call__(
        self,
        url: str,
        body: Optional[bytes] = None,
        method: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Response:
        """
        Perform a HTTP request.

        Args:
            url: URL of resource to request.
            body: Body of request. Defaults to an empty body.
            method: HTTP method for request. Defaults to 'GET'.
            headers: Map of headers to set on the request. Defaults to an empty mapping.

        Returns:
            The response from the resource server.

        Raises:
            TransportError: on any transport error such as DNS resolution failure. Note that error
                status codes from the server do not raise.
        """
