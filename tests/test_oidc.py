import pytest
import requests
from jwcrypto.jwk import JWKSet
from jwcrypto.jwt import JWT

from federatedidentity import Issuer, _oidc, exceptions


def test_jwt_issuer(jwt_issuer: str, jwks_uri: str):
    r = requests.get("".join([jwt_issuer.rstrip("/"), "/.well-known/openid-configuration"]))
    r.raise_for_status()
    assert r.json()["jwks_uri"] == jwks_uri


def test_oidc_token(oidc_token: str, jwk_set: JWKSet, jwt_issuer: str):
    jwt = JWT(check_claims={"iss": jwt_issuer})
    jwt.deserialize(oidc_token, jwk_set)


def test_oidc_token_subject(oidc_token: str, oidc_subject: str):
    assert _oidc.unvalidated_claim_from_token(oidc_token, "sub") == oidc_subject


def test_oidc_token_audience(oidc_token: str, oidc_audience: str):
    assert _oidc.unvalidated_claim_from_token(oidc_token, "aud") == oidc_audience


def test_oidc_token_issuer(oidc_token: str, oidc_issuer: Issuer):
    assert _oidc.unvalidated_claim_from_token(oidc_token, "iss") == oidc_issuer.name


def test_malformed_token():
    with pytest.raises(exceptions.InvalidTokenError):
        assert _oidc.unvalidated_claim_from_token("not a JWT", "iss")


def test_missing_claim(faker, oidc_token: str):
    with pytest.raises(exceptions.InvalidTokenError):
        assert _oidc.unvalidated_claim_from_token(oidc_token, faker.slug())
