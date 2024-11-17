class FederatedIdentityError(RuntimeError):
    "Base class for all errors raised by the federatedidentity module."


class InvalidIssuerError(FederatedIdentityError):
    "The issuer claim in the JWT was not correctly formed."


class InvalidJWKSUrlError(FederatedIdentityError):
    "The JWKS URL in the OIDC discovery document was not correctly formed."


class InvalidOIDCDiscoveryDocumentError(FederatedIdentityError):
    "The OIDC discovery document was malformed."


class InvalidTokenError(FederatedIdentityError):
    "The token was malformed or could not be validated against the issuer public key."


class TransportError(FederatedIdentityError):
    "There was an error fetching a URL."


class InvalidClaimsError(FederatedIdentityError):
    "The claims in the token did not match policy."
