import json
from typing import Any

import pytest
from faker import Faker
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT
from responses import RequestsMock


@pytest.fixture
def jwt_issuer(faker: Faker, jwks_uri: str, mocked_responses: RequestsMock) -> str:
    issuer_url = faker.url(schemes=["https"]).rstrip("/")
    discovery_doc = json.dumps({"jwks_uri": jwks_uri, "issuer": issuer_url}).encode("utf8")
    discovery_doc_url = f"{issuer_url}/.well-known/openid-configuration"
    mocked_responses.get(discovery_doc_url, body=discovery_doc, content_type="application/json")
    return issuer_url


@pytest.fixture
def oidc_subject(faker: Faker) -> str:
    return faker.slug()


@pytest.fixture
def oidc_audience(faker: Faker) -> str:
    return faker.slug()


@pytest.fixture
def oidc_claims(
    faker: Faker, jwt_issuer: str, oidc_subject: str, oidc_audience: str
) -> dict[str, str]:
    return {
        "iss": jwt_issuer,
        "sub": oidc_subject,
        "aud": oidc_audience,
        "jti": faker.uuid4(),
    }


def make_jwt(claims: dict[str, str], key: JWK, alg: str) -> str:
    jwt = JWT(header={"alg": alg, "kid": key["kid"], "type": "JWT"}, claims=claims)
    jwt.make_signed_token(key)
    return jwt.serialize()


@pytest.fixture(params=["ES256", "RS256"])
def make_oidc_token(request, jwks: dict[str, JWK], oidc_claims: dict[str, Any]):
    def _make_oidc_token(claims: Any = None):
        return make_jwt(
            claims if claims is not None else oidc_claims, jwks[request.param], request.param
        )

    return _make_oidc_token


@pytest.fixture
def oidc_token(make_oidc_token):
    return make_oidc_token()
