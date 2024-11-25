import json
from collections.abc import Callable, Iterable
from typing import Any, NewType, Optional, Union, cast

from . import _oidc
from .exceptions import InvalidClaimsError

ClaimVerifier = Union[dict[str, Any], Callable[[dict[str, Any]], None]]
"""
Type representing a claim verifier. A claim verifier may be a dictionary of acceptable claim values
or a callable which takes the claims dictionary. A claims verifier callable should raise
[`InvalidClaimsError`][federatedidentity.exceptions.InvalidClaimsError] if the claims do not match
the expected values.
"""

AnyAudienceType = NewType("AnyAudienceType", object)

ANY_AUDIENCE = cast(AnyAudienceType, object())
"""
Special value which can be passed as the `valid_audiences` parameter to
[verify_id_token][federatedidentity.verify_id_token] which matches any audience.
"""


def verify_id_token(
    token: Union[str, bytes],
    valid_issuers: Iterable[_oidc.Issuer],
    valid_audiences: Iterable[Union[str, AnyAudienceType]],
    *,
    required_claims: Optional[Iterable[ClaimVerifier]] = None,
) -> dict[str, Any]:
    """
    Verify an OIDC identity token.

    Returns:
        the token's claims dictionary.

    Parameters:
        token: OIDC token to verify. If a [bytes][] object is passed it is decoded using the ASCII
            codec before verification.
        valid_issuers: Iterable of valid issuers. At least one Issuer must match the token issuer
            for verification to succeed.
        valid_audiences: Iterable of valid audiences. At least one audience must match the `aud`
            claim for verification to succeed. An audience is either a literal string or a callable
            which takes an audience and returns True if it is valid.
        required_claims: Iterable of required claim verifiers. Claims are passed to verifiers after
            the token's signature has been verified. Claims required by OIDC are always
            validated. All claim verifiers must pass for verification to succeed.

    Raises:
        federatedidentity.exceptions.FederatedIdentityError: The token failed verification.
        UnicodeDecodeError: The token could not be decoded into an ASCII string.
    """
    if isinstance(token, bytes):
        token = token.decode("ascii")

    unvalidated_claims = _oidc.unvalidated_claims_from_token(token)

    # For required claims, see: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    for claim in ["iss", "sub", "aud", "exp", "iat"]:
        if claim not in unvalidated_claims:
            raise InvalidClaimsError(f"'{claim}' claim not present in token")

    # Check that the token "aud" claim matches at least one of our expected audiences.
    if not any(
        (audience == unvalidated_claims["aud"]) or (audience is ANY_AUDIENCE)
        for audience in valid_audiences
    ):
        raise InvalidClaimsError(
            f"Token audience '{unvalidated_claims['aud']}' did not match any valid audience"
        )

    # Determine which issuer matches the token.
    for issuer in valid_issuers:
        if issuer.name == unvalidated_claims["iss"]:
            break
    else:
        # No issuer matched the token if the for loop exited without "break".
        raise InvalidClaimsError(
            f"Token issuer '{unvalidated_claims['iss']}' did not match any valid issuer"
        )

    # Note: validate_token() validates "exp", "iat" and "nbf" claims and that the "alg" header has
    # an appropriate value.
    verified_claims = json.loads(_oidc.validate_token(token, issuer.key_set).claims)

    # Verify claims against any ClaimVerifier-s passed.
    _verify_claims(verified_claims, required_claims)

    return verified_claims


def _verify_claims(claims: dict[str, Any], required_claims: Optional[Iterable[ClaimVerifier]]):
    required_claims = required_claims if required_claims is not None else []
    for claims_verifier in required_claims:
        if callable(claims_verifier):
            claims_verifier(claims)
        else:
            for claim, value in claims_verifier.items():
                if claim not in claims:
                    raise InvalidClaimsError(f"Required claim '{claim}' not present in token")
                if claims[claim] != value:
                    raise InvalidClaimsError(
                        f"Required claim '{claim}' has invalid value {claims[claim]!r}. "
                        f"Expected {value!r}."
                    )
