"""
Utility functions for constructing claims verifiers suitable for passing to
[verify_id_token][federatedidentity.verify_id_token].

"""

from collections.abc import Container, Iterable
from typing import Any

from ._verify import ClaimVerifier, _verify_claims
from .exceptions import InvalidClaimsError


def all_claims_present(claim_names: Iterable[str]) -> ClaimVerifier:
    """
    Verifies that all claims in `required_claims` are present.

    Arguments:
        claim_names: Iterable of claim names.

    Returns:
        A claims verifier.
    """

    def verify(claims: dict[str, Any]):
        missing_claims = set(claim_names) - set(claims.keys())
        if len(missing_claims) > 0:
            raise InvalidClaimsError(
                "Required claims "
                f"{', '.join(repr(c) for c in missing_claims)} not present in token"
            )

    return verify


def only_for_issuers(
    issuers: Container[str], required_claims: Iterable[ClaimVerifier]
) -> ClaimVerifier:
    """
    Apply claim verifiers only for a particular set of issuers.

    Arguments:
        issuers: Issuer names which should have the claims verifiers in `required_claims` applied.
        required_claims: Iterable of claim verifiers to run if the token matches one of the issuers
            in `issuers`.

    Returns:
        A claims verifier.
    """

    def verify(claims: dict[str, Any]):
        if claims["iss"] not in issuers:
            return
        _verify_claims(claims, required_claims)

    return verify
