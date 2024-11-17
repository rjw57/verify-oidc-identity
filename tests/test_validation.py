import datetime
from typing import Any

import pytest
from faker import Faker
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from jwcrypto.jwt import JWT

from federatedidentity import AsyncOIDCTokenIssuer, OIDCTokenIssuer
from federatedidentity import exceptions as exc
from federatedidentity import oidc

from .oidcfixtures import make_jwt


def test_oidc_token_issuer(oidc_token: str, jwt_issuer: str):
    assert oidc.unvalidated_claim_from_token(oidc_token, "iss") == jwt_issuer


def test_token_payload_is_not_json(ec_jwk: JWK):
    jws = JWS("not json")
    jws.add_signature(
        ec_jwk, alg="ES256", protected={"alg": "ES256", "kid": ec_jwk["kid"], "type": "JWT"}
    )
    with pytest.raises(exc.InvalidTokenError):
        oidc.unvalidated_claim_from_token(jws.serialize(compact=True), "iss")


def test_missing_issuer_claim(oidc_claims: dict[str, str], ec_jwk: JWK):
    del oidc_claims["iss"]
    jwt = JWT(
        header={"alg": "ES256", "kid": ec_jwk["kid"], "type": "JWT"},
        claims=oidc_claims,
    )
    jwt.make_signed_token(ec_jwk)
    token = jwt.serialize()
    with pytest.raises(exc.InvalidTokenError):
        oidc.unvalidated_claim_from_token(token, "iss")


def test_basic_verification(faker: Faker, oidc_token: str, oidc_audience: str, jwt_issuer: str):
    provider = OIDCTokenIssuer(jwt_issuer, oidc_audience)
    provider.prepare()
    provider.validate(oidc_token)


@pytest.mark.asyncio
async def test_basic_async_verification(
    faker: Faker, oidc_token: str, oidc_audience: str, jwt_issuer: str
):
    provider = AsyncOIDCTokenIssuer(jwt_issuer, oidc_audience)
    await provider.prepare()
    provider.validate(oidc_token)


def test_mismatched_audience(faker: Faker, oidc_token: str, jwt_issuer: str):
    provider = OIDCTokenIssuer(jwt_issuer, faker.url(schemes=["https"]))
    provider.prepare()
    with pytest.raises(exc.InvalidClaimsError):
        provider.validate(oidc_token)


def test_issuer_not_url(oidc_token: str, oidc_audience: str):
    provider = OIDCTokenIssuer("-not a url-", oidc_audience)
    with pytest.raises(exc.InvalidIssuerError):
        provider.prepare()


def test_issuer_bad_scheme(faker: Faker, oidc_token: str, oidc_audience: str):
    provider = OIDCTokenIssuer(faker.url(schemes=["http"]), oidc_audience)
    with pytest.raises(exc.InvalidIssuerError):
        provider.prepare()


@pytest.mark.parametrize("alg", ["RS256", "ES256"])
def test_mismatched_issuer(
    alg: str,
    faker: Faker,
    oidc_claims: dict[str, str],
    oidc_audience: str,
    jwt_issuer: str,
    jwks: dict[str, JWK],
):
    provider = OIDCTokenIssuer(jwt_issuer, oidc_audience)
    provider.prepare()
    iss = faker.url(schemes=["https"])
    oidc_claims["iss"] = iss
    token = make_jwt(oidc_claims, jwks[alg], alg)
    with pytest.raises(exc.InvalidClaimsError):
        provider.validate(token)


@pytest.mark.parametrize("alg", ["RS256", "ES256"])
def test_exp_claim_in_past(
    alg: str,
    faker: Faker,
    oidc_claims: dict[str, Any],
    oidc_audience: str,
    jwt_issuer: str,
    jwks: dict[str, JWK],
):
    provider = OIDCTokenIssuer(jwt_issuer, oidc_audience)
    provider.prepare()
    oidc_claims["exp"] = datetime.datetime.now(datetime.UTC).timestamp() - 100000
    token = make_jwt(oidc_claims, jwks[alg], alg)
    with pytest.raises(exc.InvalidTokenError):
        provider.validate(token)


@pytest.mark.parametrize("alg", ["RS256", "ES256"])
def test_nbf_claim_in_future(
    alg: str,
    faker: Faker,
    oidc_claims: dict[str, Any],
    oidc_audience: str,
    jwt_issuer: str,
    jwks: dict[str, JWK],
):
    provider = OIDCTokenIssuer(jwt_issuer, oidc_audience)
    provider.prepare()
    oidc_claims["nbf"] = datetime.datetime.now(datetime.UTC).timestamp() + 100000
    token = make_jwt(oidc_claims, jwks[alg], alg)
    with pytest.raises(exc.InvalidTokenError):
        provider.validate(token)
