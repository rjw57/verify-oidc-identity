import pytest
from faker import Faker

from federatedidentity import Issuer, verifiers, verify_id_token
from federatedidentity.exceptions import InvalidClaimsError


@pytest.mark.parametrize("claims", [["sub"], ["sub", "iat"]])
def test_all_claims_present_valid(
    claims: list[str], oidc_token: str, oidc_audience: str, oidc_issuer: Issuer
):
    verify_id_token(
        oidc_token,
        [oidc_issuer],
        [oidc_audience],
        required_claims=[
            verifiers.all_claims_present(claims),
        ],
    )


@pytest.mark.parametrize("claims", [["missing"], ["sub", "missing", "iat"]])
def test_all_claims_present_invalid(
    claims: list[str], oidc_token: str, oidc_audience: str, oidc_issuer: Issuer
):
    with pytest.raises(InvalidClaimsError):
        verify_id_token(
            oidc_token,
            [oidc_issuer],
            [oidc_audience],
            required_claims=[
                verifiers.all_claims_present(claims),
            ],
        )


def test_only_for_issuers_non_matching(
    faker: Faker, oidc_token: str, oidc_audience: str, oidc_issuer: Issuer
):
    verify_id_token(
        oidc_token,
        [oidc_issuer],
        [oidc_audience],
        required_claims=[
            verifiers.only_for_issuers(
                [faker.url(schemes=["https"])],
                [verifiers.all_claims_present(["not-expected-to-be-present"])],
            )
        ],
    )


def test_only_for_issuers_matching_fail(oidc_token: str, oidc_audience: str, oidc_issuer: Issuer):
    with pytest.raises(InvalidClaimsError):
        verify_id_token(
            oidc_token,
            [oidc_issuer],
            [oidc_audience],
            required_claims=[
                verifiers.only_for_issuers(
                    [oidc_issuer.name],
                    [verifiers.all_claims_present(["not-expected-to-be-present"])],
                )
            ],
        )


def test_only_for_issuers_matching_succeed(
    oidc_token: str, oidc_audience: str, oidc_issuer: Issuer
):
    verify_id_token(
        oidc_token,
        [oidc_issuer],
        [oidc_audience],
        required_claims=[
            verifiers.only_for_issuers(
                [oidc_issuer.name],
                [verifiers.all_claims_present(["sub"])],
            )
        ],
    )
