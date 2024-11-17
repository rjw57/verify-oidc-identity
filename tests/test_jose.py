import requests
from jwcrypto.jwk import JWKSet


def test_jwk_set_present(jwk_set: JWKSet, ec_jwk_kid: str, rsa_jwk_kid):
    assert jwk_set.get_key(ec_jwk_kid) is not None
    assert jwk_set.get_key(ec_jwk_kid)["kty"] == "EC"
    assert jwk_set.get_key(rsa_jwk_kid) is not None
    assert jwk_set.get_key(rsa_jwk_kid)["kty"] == "RSA"


def test_jwks_uri(jwks_uri: str):
    r = requests.get(jwks_uri)
    r.raise_for_status()
    jwks = JWKSet.from_json(r.content)
    assert len(jwks["keys"]) > 0
