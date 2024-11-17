import json

import pytest
from faker import Faker
from jwcrypto.jwk import JWKSet

from federatedidentity import exceptions, oidc
from federatedidentity.transport.requests import async_request, request


def test_basic_case(jwt_issuer: str, jwk_set: JWKSet):
    fetched_jwk_set = oidc.fetch_jwks(oidc.validate_issuer(jwt_issuer), request)
    assert fetched_jwk_set == jwk_set


@pytest.mark.asyncio
async def test_basic_case_async(jwt_issuer: str, jwk_set: JWKSet):
    fetched_jwk_set = await oidc.async_fetch_jwks(oidc.validate_issuer(jwt_issuer), async_request)
    assert fetched_jwk_set == jwk_set


@pytest.mark.parametrize("field", ["jwks_uri", "issuer"])
def test_missing_field_in_discovery_doc(field: str, jwt_issuer: str, mocked_responses):
    doc_url = oidc.oidc_discovery_document_url(oidc.validate_issuer(jwt_issuer))
    doc = json.loads(request(doc_url).content)
    del doc[field]
    mocked_responses.remove("GET", doc_url)
    mocked_responses.get(doc_url, body=json.dumps(doc), content_type="application/json")
    with pytest.raises(exceptions.InvalidOIDCDiscoveryDocumentError):
        oidc.fetch_jwks(jwt_issuer, request)


def test_discovery_doc_not_present(jwt_issuer: str, mocked_responses):
    doc_url = oidc.oidc_discovery_document_url(oidc.validate_issuer(jwt_issuer))
    doc_body = request(doc_url).content
    mocked_responses.remove("GET", doc_url)
    mocked_responses.get(doc_url, body=doc_body, status=404, content_type="application/json")
    with pytest.raises(exceptions.TransportError):
        oidc.fetch_jwks(jwt_issuer, request)


@pytest.mark.asyncio
async def test_discovery_doc_not_present_async(jwt_issuer: str, mocked_responses):
    doc_url = oidc.oidc_discovery_document_url(oidc.validate_issuer(jwt_issuer))
    doc_body = (await async_request(doc_url)).content
    mocked_responses.remove("GET", doc_url)
    mocked_responses.get(doc_url, body=doc_body, status=404, content_type="application/json")
    with pytest.raises(exceptions.TransportError):
        await oidc.async_fetch_jwks(jwt_issuer, async_request)


def test_discovery_doc_not_json(jwt_issuer: str, mocked_responses):
    doc_url = oidc.oidc_discovery_document_url(oidc.validate_issuer(jwt_issuer))
    mocked_responses.remove("GET", doc_url)
    mocked_responses.get(doc_url, body="this is not json", content_type="application/json")
    with pytest.raises(exceptions.InvalidOIDCDiscoveryDocumentError):
        oidc.fetch_jwks(jwt_issuer, request)


def test_mismatched_issuer_in_discovery_doc(faker: Faker, jwt_issuer: str, mocked_responses):
    doc_url = oidc.oidc_discovery_document_url(oidc.validate_issuer(jwt_issuer))
    doc = json.loads(request(doc_url).content)
    doc["issuer"] = faker.url()
    mocked_responses.remove("GET", doc_url)
    mocked_responses.get(doc_url, body=json.dumps(doc), content_type="application/json")
    with pytest.raises(exceptions.InvalidOIDCDiscoveryDocumentError):
        oidc.fetch_jwks(jwt_issuer, request)


def test_issuer_not_url():
    with pytest.raises(exceptions.InvalidIssuerError) as e:
        oidc.fetch_jwks("not/a/ url", request)
    assert str(e.value) == "Issuer is not a valid URL."


def test_issuer_not_https(faker: Faker):
    with pytest.raises(exceptions.InvalidIssuerError) as e:
        oidc.fetch_jwks(faker.url(schemes=["http"]), request)
    assert str(e.value) == "Issuer does not have a https scheme."


def test_jwks_uri_not_url(jwt_issuer: str, mocked_responses):
    doc_url = oidc.oidc_discovery_document_url(oidc.validate_issuer(jwt_issuer))
    doc = json.loads(request(doc_url).content)
    doc["jwks_uri"] = "not a /url"
    mocked_responses.remove("GET", doc_url)
    mocked_responses.get(doc_url, body=json.dumps(doc), content_type="application/json")
    with pytest.raises(exceptions.InvalidJWKSUrlError) as e:
        oidc.fetch_jwks(jwt_issuer, request)
    assert str(e.value) == "JWKS URL is not a valid URL."


def test_jwks_uri_not_https(faker: Faker, jwt_issuer: str, mocked_responses):
    doc_url = oidc.oidc_discovery_document_url(oidc.validate_issuer(jwt_issuer))
    doc = json.loads(request(doc_url).content)
    doc["jwks_uri"] = faker.url(schemes=["http"])
    mocked_responses.remove("GET", doc_url)
    mocked_responses.get(doc_url, body=json.dumps(doc), content_type="application/json")
    with pytest.raises(exceptions.InvalidJWKSUrlError) as e:
        oidc.fetch_jwks(jwt_issuer, request)
    assert str(e.value) == "JWKS URL does not have a https scheme."
