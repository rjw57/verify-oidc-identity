import pytest
import responses
from faker import Faker
from jwcrypto.jwk import JWK, JWKSet


@pytest.fixture
def ec_jwk_kid(faker: Faker) -> str:
    return faker.slug()


@pytest.fixture
def ec_jwk(ec_jwk_kid) -> JWK:
    return JWK.generate(kty="EC", crv="P-256", kid=ec_jwk_kid)


@pytest.fixture
def rsa_jwk_kid(faker: Faker) -> str:
    return faker.slug()


@pytest.fixture
def rsa_jwk(rsa_jwk_kid) -> JWK:
    return JWK.generate(kty="RSA", size=2048, kid=rsa_jwk_kid)


@pytest.fixture
def jwks(ec_jwk, rsa_jwk) -> dict[str, JWK]:
    return {"ES256": ec_jwk, "RS256": rsa_jwk}


@pytest.fixture
def jwk_set(ec_jwk, rsa_jwk) -> JWKSet:
    s = JWKSet()
    s["keys"].add(ec_jwk)
    s["keys"].add(rsa_jwk)
    return s


@pytest.fixture
def jwks_uri(faker: Faker, jwk_set: JWKSet, mocked_responses: responses.RequestsMock) -> str:
    url = faker.url(schemes=["https"])
    mocked_responses.get(
        url, body=jwk_set.export(private_keys=False), content_type="application/json"
    )
    return url
