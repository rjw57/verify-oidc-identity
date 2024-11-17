import pytest
import requests
import responses
from jwcrypto.jwk import JWKSet
from jwcrypto.jwt import JWT

from federatedidentity import oidc


@pytest.fixture
def unprepared_oidc_token_issuer(jwt_issuer, oidc_audience):
    return oidc.OIDCTokenIssuer(issuer=jwt_issuer, audience=oidc_audience)


@pytest.fixture
def prepared_oidc_token_issuer(jwt_issuer, oidc_audience):
    issuer = oidc.OIDCTokenIssuer(issuer=jwt_issuer, audience=oidc_audience)
    issuer.prepare()
    return issuer


def test_jwt_issuer(jwt_issuer: str, jwks_uri: str):
    r = requests.get("".join([jwt_issuer.rstrip("/"), "/.well-known/openid-configuration"]))
    r.raise_for_status()
    assert r.json()["jwks_uri"] == jwks_uri


def test_oidc_token(oidc_token: str, jwk_set: JWKSet, jwt_issuer: str):
    jwt = JWT(check_claims={"iss": jwt_issuer})
    jwt.deserialize(oidc_token, jwk_set)


def test_oidc_token_issuer(oidc_token: str, jwt_issuer: str):
    assert oidc.unvalidated_claim_from_token(oidc_token, "iss") == jwt_issuer


def test_oidc_token_subject(oidc_token: str, oidc_subject: str):
    assert oidc.unvalidated_claim_from_token(oidc_token, "sub") == oidc_subject


def test_oidc_token_audience(oidc_token: str, oidc_audience: str):
    assert oidc.unvalidated_claim_from_token(oidc_token, "aud") == oidc_audience


def test_basic_validated(oidc_token, oidc_claims, prepared_oidc_token_issuer):
    assert prepared_oidc_token_issuer.validate(oidc_token) == oidc_claims


@pytest.mark.parametrize("missing_claim", ["iss", "aud"])
def test_oidc_token_missing_claim(
    missing_claim, make_oidc_token, oidc_claims, prepared_oidc_token_issuer
):
    claims = {**oidc_claims}
    del claims[missing_claim]
    with pytest.raises(oidc.InvalidClaimsError):
        prepared_oidc_token_issuer.validate(make_oidc_token(claims))


def test_unprepared_issuer(oidc_token, unprepared_oidc_token_issuer):
    with pytest.raises(ValueError):
        unprepared_oidc_token_issuer.validate(oidc_token)


def test_multiple_prepare_only_fetches_once(
    oidc_token, oidc_claims, unprepared_oidc_token_issuer, mocked_responses: responses.RequestsMock
):
    mocked_responses.assert_call_count(oidc.oidc_discovery_document_url(oidc_claims["iss"]), 0)
    unprepared_oidc_token_issuer.prepare()
    mocked_responses.assert_call_count(oidc.oidc_discovery_document_url(oidc_claims["iss"]), 1)
    unprepared_oidc_token_issuer.prepare()
    mocked_responses.assert_call_count(oidc.oidc_discovery_document_url(oidc_claims["iss"]), 1)
    assert unprepared_oidc_token_issuer.validate(oidc_token) == oidc_claims
    mocked_responses.assert_call_count(oidc.oidc_discovery_document_url(oidc_claims["iss"]), 1)
