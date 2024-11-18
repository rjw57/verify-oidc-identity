#!/usr/bin/env python3
"""
Script to verify an OIDC identity token as issued by Google by means of the gcloud command
line tool. For example:

    $ gcloud auth login
    ...
    $ gcloud auth print-identity-token | ./examples/verify-google-id-token.py
    Verified token claims:
    {
      "iss": "https://accounts.google.com",
      "azp": "32555940559.apps.googleusercontent.com",
      "aud": "32555940559.apps.googleusercontent.com",
      "sub": "12345678901234567890",
      "email": "example@example.com",
      "email_verified": true,
      "at_hash": "abcdefghijklmn",
      "iat": 1731940000,
      "exp": 1731953600
    }

"""
import json
import sys

from federatedidentity import Issuer, verifiers, verify_id_token
from federatedidentity.exceptions import FederatedIdentityError

# Read JWT token from standard input.
token = sys.stdin.read().strip()

# The "aud" claim which is present in tokens created by `gcloud auth print-identity-token`.
expected_audience = "32555940559.apps.googleusercontent.com"

# Verify and extract the payload checking that it is issued by Google.
try:
    verified_claims = verify_id_token(
        token,
        valid_issuers=[Issuer.from_discovery("https://accounts.google.com")],
        valid_audiences=[expected_audience],
        required_claims=[
            # The 'azp' claim must be present and *also* match the expected audience.
            {"azp": expected_audience},
            # Check that the 'sub' claim is present in the claims.
            verifiers.all_claims_present(["sub"]),
        ],
    )
except FederatedIdentityError as e:
    print(f"Token failed verification: {e}", file=sys.stderr)
    sys.exit(1)

# Write the verified claims to standard output as a JSON document.
print(f"Verified token claims:\n{json.dumps(verified_claims, indent=2)}")
