import pytest
import responses

from .josefixtures import *  # noqa: F401, F403
from .oidcfixtures import *  # noqa: F401, F403


@pytest.fixture(autouse=True)
def mocked_responses() -> responses.RequestsMock:
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        yield rsps
