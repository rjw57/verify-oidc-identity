import json
from collections.abc import Mapping
from typing import Any, NewType, Optional, cast
from urllib.parse import urlparse

from jwcrypto.common import JWException
from jwcrypto.jwk import JWKSet
from jwcrypto.jwt import JWT
from validators.url import url as validate_url

from .baseprovider import AsyncBaseProvider, BaseProvider
from .exceptions import (
    InvalidClaimsError,
    InvalidIssuerError,
    InvalidJWKSUrlError,
    InvalidOIDCDiscoveryDocumentError,
    InvalidTokenError,
    TransportError,
)
from .transport import AsyncRequestBase, RequestBase
from .transport import requests as requests_transport

ValidatedIssuer = NewType("ValidatedIssuer", str)
ValidatedJWKSUrl = NewType("ValidatedJWKSUrl", str)
UnvalidatedClaims = NewType("UnvalidatedClaims", dict[str, Any])


def validate_issuer(unvalidated_issuer: str) -> ValidatedIssuer:
    """
    Validate issuer is correctly formed.

    Args:
        unvalidated_issuer: issuer string which needs validating.

    Returns:
        The issuer if it is validated.

    Raises:
        InvalidIssuer: the issuer is not correctly formed.
    """
    if not validate_url(unvalidated_issuer):
        raise InvalidIssuerError("Issuer is not a valid URL.")
    if urlparse(unvalidated_issuer).scheme != "https":
        raise InvalidIssuerError("Issuer does not have a https scheme.")
    return cast(ValidatedIssuer, unvalidated_issuer)


def validate_jwks_uri(unvalidated_jwks_uri: str) -> ValidatedJWKSUrl:
    """
    Validate JWKS URL is correctly formed.

    Args:
        unvalidated_jwks_uri: URL which needs validating.

    Returns:
        The url if it is validated.

    Raises:
        InvalidJWKSUrl: the JWKS URL is not correctly formed.
    """
    if not validate_url(unvalidated_jwks_uri):
        raise InvalidJWKSUrlError("JWKS URL is not a valid URL.")
    if urlparse(unvalidated_jwks_uri).scheme != "https":
        raise InvalidJWKSUrlError("JWKS URL does not have a https scheme.")
    return cast(ValidatedJWKSUrl, unvalidated_jwks_uri)


def oidc_discovery_document_url(issuer: ValidatedIssuer) -> str:
    "Form an OIDC discovery document from a validated issuer."
    return "".join([issuer.rstrip("/"), "/.well-known/openid-configuration"])


def _jwks_uri_from_oidc_discovery_document(
    expected_issuer: str, oidc_discovery_doc_content: bytes
) -> ValidatedJWKSUrl:
    try:
        oidc_discovery_doc = json.loads(oidc_discovery_doc_content)
    except json.JSONDecodeError as e:
        raise InvalidOIDCDiscoveryDocumentError(f"Error decoding OIDC discovery document: {e}")

    try:
        issuer = oidc_discovery_doc["issuer"]
    except KeyError:
        raise InvalidOIDCDiscoveryDocumentError(
            "'issuer' key not present in OIDC discovery document."
        )
    if issuer != expected_issuer:
        raise InvalidOIDCDiscoveryDocumentError(
            f"Issuer {issuer!r} in OIDC discovery document does not "
            f"match expected issuer {expected_issuer!r}."
        )

    try:
        jwks_uri = validate_jwks_uri(oidc_discovery_doc["jwks_uri"])
    except KeyError:
        raise InvalidOIDCDiscoveryDocumentError(
            "'jwks_uri' key not present in OIDC discovery document."
        )
    return jwks_uri


def _request_json(url: str, request: RequestBase) -> bytes:
    """
    Wrapper arround RequestBase which requests a JSON document and raises TransportError on an
    error status code. The requested JSON document is not parsed.

    Returns:
        The response contents.
    """
    r = request(url, headers={"Accept": "application/json"})
    if r.status_code >= 400:
        raise TransportError(
            f"Error status when requesting {url!r}: {r.status_code}",
        )
    return r.content


async def _async_request_json(url: str, request: AsyncRequestBase) -> bytes:
    """
    Wrapper arround RequestBase which requests a JSON document and raises TransportError on an
    error status code. The requested JSON document is not parsed.

    Returns:
        The response contents.
    """
    r = await request(url, headers={"Accept": "application/json"})
    if r.status_code >= 400:
        raise TransportError(
            f"Error status when requesting {url!r}: {r.status_code}",
        )
    return r.content


def fetch_jwks(unvalidated_issuer: str, request: RequestBase) -> JWKSet:
    "Fetch a JWK set from an unvalidated issuer."
    oidc_discovery_doc = _request_json(
        oidc_discovery_document_url(validate_issuer(unvalidated_issuer)), request
    )
    jwks_uri = _jwks_uri_from_oidc_discovery_document(unvalidated_issuer, oidc_discovery_doc)
    return JWKSet.from_json(_request_json(jwks_uri, request))


async def async_fetch_jwks(unvalidated_issuer: str, request: AsyncRequestBase) -> JWKSet:
    "Fetch a JWK set from an unvalidated issuer using an asynchronous fetcher."
    oidc_discovery_doc = await _async_request_json(
        oidc_discovery_document_url(validate_issuer(unvalidated_issuer)), request
    )
    jwks_uri = _jwks_uri_from_oidc_discovery_document(unvalidated_issuer, oidc_discovery_doc)
    return JWKSet.from_json(await _async_request_json(jwks_uri, request))


def unvalidated_claims_from_token(unvalidated_token: str) -> UnvalidatedClaims:
    "Parse and extract unverified claims from the token."
    try:
        jwt = JWT.from_jose_token(unvalidated_token)
    except Exception:
        raise InvalidTokenError("Could not parse token as JWT")
    try:
        payload = json.loads(jwt.token.objects["payload"])
    except (json.JSONDecodeError, KeyError):
        raise InvalidTokenError("Could not decode token payload as JSON.")
    return cast(UnvalidatedClaims, payload)


def unvalidated_claim_from_token(unvalidated_token: str, claim: str) -> str:
    "Parse and extract an unvalidated claim from an unvalidated token."
    claims = unvalidated_claims_from_token(unvalidated_token)
    try:
        return claims[claim]
    except KeyError:
        raise InvalidTokenError(f"Claim '{claim}' not present in token paylaod.")


def validate_token(unvalidated_token: str, jwk_set: JWKSet) -> JWT:
    try:
        jwt = JWT(algs=["RS256", "ES256"], expected_type="JWS")
        jwt.deserialize(unvalidated_token, jwk_set)
    except JWException as e:
        raise InvalidTokenError(f"Invalid token: {e}")
    return jwt


class _BaseOIDCTokenIssuer:

    issuer: str
    audience: str
    _key_set: Optional[JWKSet]

    def __init__(self, issuer: str, audience: str):
        self.issuer = issuer
        self.audience = audience
        self._key_set = None

    def validate(self, credential: str) -> Mapping[str, Any]:
        """
        Validate a credential as being issued by this provider, having the required claims and
        those claims having expected values.

        Returns the verified claims as a mapping.

        Raises:
            FederatedIdentityError: if the token is invalid
            ValueError: if prepare() has not been called
        """
        if self._key_set is None:
            raise ValueError("prepare() must have been called prior to validation")

        unvalidated_claims = unvalidated_claims_from_token(credential)

        if "iss" not in unvalidated_claims:
            raise InvalidClaimsError("'iss' claim missing from token")
        if unvalidated_claims["iss"] != self.issuer:
            raise InvalidClaimsError(
                f"'iss' claims has value '{unvalidated_claims['iss']}', "
                f"expected '{self.issuer}'."
            )

        if "aud" not in unvalidated_claims:
            raise InvalidClaimsError("'aud' claim is missing from token")
        if unvalidated_claims["aud"] != self.audience:
            raise InvalidClaimsError(
                f"'aud' claims has value '{unvalidated_claims['aud']}', "
                f"expected '{self.audience}'."
            )

        return json.loads(validate_token(credential, self._key_set).claims)


class OIDCTokenIssuer(_BaseOIDCTokenIssuer, BaseProvider):
    """
    Represents an issuer of federated credentials in the form of OpenID Connect identity tokens.

    The issuer must publish an OIDC Discovery document as per
    https://openid.net/specs/openid-connect-discovery-1_0.html.

    The id token is verified to have a signature which matches one of the keys in the issuer's
    published key set and that it has at least an "iss", "sub", "aud" and "exp" claim. If an "exp"
    claim is present, it is verified to be in the future. If a "nbf" claim is present it is
    verified to be in the past and if a "iat" claim is present it is verified to be an integer.

    Args:
        issuer: issuer of tokens as represented in the "iss" claim of the OIDC token.
        audience: expected audience of tokens as represented in the "aud" claim of the OIDC token.
    """

    def prepare(self, request: Optional[RequestBase] = None) -> None:
        """
        Prepare this issuer for token verification, fetching the issuer's public key if necessary.
        The public key is only fetched once so it is safe to call this method repeatedly.

        Args:
            request: HTTP transport to use to fetch the issuer public key set. Defaults to a
                transport based on the requests library.

        Raises:
            FederatedIdentityError: if the issuer, OIDC discovery document or JWKS is invalid or
                some transport error ocurred.
        """
        if self._key_set is not None:
            return
        request = request if request is not None else requests_transport.request
        self._key_set = fetch_jwks(self.issuer, request)


class AsyncOIDCTokenIssuer(_BaseOIDCTokenIssuer, AsyncBaseProvider):
    """
    Asynchronous version of OIDCTokenIssuer. The only difference being that prepare() takes an
    optional AsyncRequestBase and must be awaited.

    """

    async def prepare(self, request: Optional[AsyncRequestBase] = None) -> None:
        """
        Prepare this issuer for token verification, fetching the issuer's public key if necessary.
        The public key is only fetched once so it is safe to call this method repeatedly.

        Args:
            request: Asynchronous HTTP transport to use to fetch the issuer public key set.
                Defaults to a transport based on the requests library which runs in a separate
                thread.

        Raises:
            FederatedIdentityError: if the issuer, OIDC discovery document or JWKS is invalid or
                some transport error ocurred.
        """
        if self._key_set is not None:
            return
        request = request if request is not None else requests_transport.async_request
        self._key_set = await async_fetch_jwks(self.issuer, request)
