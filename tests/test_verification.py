import datetime
from typing import Any
from unittest import mock

import pytest
from faker import Faker
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from jwcrypto.jwt import JWT

from federatedidentity import Issuer
from federatedidentity import exceptions as exc
from federatedidentity import verify_id_token

from .oidcfixtures import make_jwt


def test_basic_verification(
    faker: Faker, oidc_token: str, oidc_audience: str, oidc_issuer: Issuer
):
    verify_id_token(oidc_token, [oidc_issuer], [oidc_audience])


def test_auto_decode(faker: Faker, oidc_token: str, oidc_audience: str, oidc_issuer: Issuer):
    verify_id_token(oidc_token.encode("ascii"), [oidc_issuer], [oidc_audience])


def test_non_ascii_token(faker: Faker, oidc_token: str, oidc_audience: str, oidc_issuer: Issuer):
    with pytest.raises(UnicodeDecodeError):
        verify_id_token(
            "\N{LATIN SMALL LETTER E}\N{COMBINING CIRCUMFLEX ACCENT}".encode("utf8"),
            [oidc_issuer],
            [oidc_audience],
        )


def test_good_subject(oidc_token: str, oidc_audience: str, oidc_issuer: Issuer, oidc_subject: str):
    verify_id_token(
        oidc_token, [oidc_issuer], [oidc_audience], required_claims=[{"sub": oidc_subject}]
    )


def test_bad_subject(
    faker: Faker, oidc_token: str, oidc_audience: str, oidc_issuer: Issuer, oidc_subject: str
):
    with pytest.raises(exc.InvalidClaimsError):
        verify_id_token(
            oidc_token, [oidc_issuer], [oidc_audience], required_claims=[{"sub": faker.slug()}]
        )


def test_claim_verifier_missing_claim(
    faker: Faker, oidc_token: str, oidc_audience: str, oidc_issuer: Issuer, oidc_subject: str
):
    with pytest.raises(exc.InvalidClaimsError):
        verify_id_token(
            oidc_token,
            [oidc_issuer],
            [oidc_audience],
            required_claims=[{"some-other-claim": faker.slug()}],
        )


def test_claims_verifier_callable(
    faker: Faker,
    oidc_token: str,
    oidc_audience: str,
    oidc_issuer: Issuer,
    oidc_subject: str,
    oidc_claims: dict[str, str],
):
    message = faker.bothify("####????")
    validator = mock.Mock(side_effect=exc.InvalidClaimsError(message))
    with pytest.raises(exc.InvalidClaimsError, match=message):
        verify_id_token(
            oidc_token,
            [oidc_issuer],
            [oidc_audience],
            required_claims=[{"sub": oidc_subject}, validator],
        )
    validator.assert_called_once_with(oidc_claims)


def test_token_payload_is_not_json(ec_jwk: JWK, oidc_issuer, oidc_audience):
    jws = JWS("not json")
    jws.add_signature(
        ec_jwk, alg="ES256", protected={"alg": "ES256", "kid": ec_jwk["kid"], "type": "JWT"}
    )
    with pytest.raises(exc.InvalidTokenError):
        verify_id_token(jws.serialize(compact=True), [oidc_issuer], [oidc_audience])


@pytest.mark.parametrize("claim", ["iss", "sub", "aud", "iat", "exp"])
def test_missing_required_claim(
    claim, oidc_claims: dict[str, str], ec_jwk: JWK, oidc_audience, oidc_issuer
):
    # Claims are OK as is
    jwt = JWT(
        header={"alg": "ES256", "kid": ec_jwk["kid"], "type": "JWT"},
        claims=oidc_claims,
    )
    jwt.make_signed_token(ec_jwk)
    verify_id_token(jwt.serialize(), [oidc_issuer], [oidc_audience])

    del oidc_claims[claim]
    jwt = JWT(
        header={"alg": "ES256", "kid": ec_jwk["kid"], "type": "JWT"},
        claims=oidc_claims,
    )
    jwt.make_signed_token(ec_jwk)
    with pytest.raises(exc.InvalidClaimsError):
        verify_id_token(jwt.serialize(), [oidc_issuer], [oidc_audience])


def test_mismatched_audience(faker: Faker, oidc_token: str, oidc_issuer: Issuer):
    with pytest.raises(exc.InvalidClaimsError):
        verify_id_token(oidc_token, [oidc_issuer], [faker.url(schemes=["https"])])


@pytest.mark.parametrize("issuer", ["not-a-url", "http://example.com/", "ftp://example.com/"])
def test_malformed_issuer(issuer, oidc_token: str, oidc_audience: str):
    with pytest.raises(exc.InvalidIssuerError):
        Issuer.from_discovery(issuer)


@pytest.mark.parametrize("alg", ["RS256", "ES256"])
def test_mismatched_issuer(
    alg: str,
    faker: Faker,
    oidc_claims: dict[str, str],
    oidc_audience: str,
    oidc_issuer: Issuer,
    jwks: dict[str, JWK],
):
    iss = faker.url(schemes=["https"])
    token = make_jwt({**oidc_claims, "iss": iss}, jwks[alg], alg)
    with pytest.raises(exc.InvalidClaimsError, match="Token issuer '.*' did not match"):
        verify_id_token(token, [oidc_issuer], [oidc_audience])


@pytest.mark.parametrize("alg", ["RS256", "ES256"])
def test_exp_claim_in_past(
    alg: str,
    faker: Faker,
    oidc_claims: dict[str, Any],
    oidc_audience: str,
    oidc_issuer: Issuer,
    jwks: dict[str, JWK],
):
    oidc_claims["exp"] = datetime.datetime.now(datetime.UTC).timestamp() - 100000
    token = make_jwt(oidc_claims, jwks[alg], alg)
    with pytest.raises(exc.InvalidTokenError, match="Expired"):
        verify_id_token(token, [oidc_issuer], [oidc_audience])


@pytest.mark.parametrize("alg", ["RS256", "ES256"])
def test_nbf_claim_in_future(
    alg: str,
    faker: Faker,
    oidc_claims: dict[str, Any],
    oidc_audience: str,
    oidc_issuer: Issuer,
    jwks: dict[str, JWK],
):
    oidc_claims["nbf"] = datetime.datetime.now(datetime.UTC).timestamp() + 100000
    token = make_jwt(oidc_claims, jwks[alg], alg)
    with pytest.raises(exc.InvalidTokenError, match="Valid from"):
        verify_id_token(token, [oidc_issuer], [oidc_audience])
