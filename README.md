# Python library to verify id tokens using OIDC discovery

[![PyPI - Version](https://img.shields.io/pypi/v/verify-oidc-identity)](https://pypi.org/p/verify-oidc-identity/)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/verify-oidc-identity)
[![GitHub Release](https://img.shields.io/github/v/release/rjw57/verify-oidc-identity)](https://github.com/rjw57/verify-oidc-identity/releases)
[![Test suite status](https://github.com/rjw57/verify-oidc-identity/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/rjw57/verify-oidc-identity/actions/workflows/main.yml?query=branch%3Amain)

[OpenID connect][oidc] identity tokens are a popular choice for federating identity between
different systems without the need to share secrets. For example [Trusted publishing on
PyPI](https://docs.pypi.org/trusted-publishers/) allows use of OIDC tokens created by
GitHub or GitLab CI jobs to be used to authenticate when uploading new Python packages.
Similarly, OIDC tokens can be used to authenticate to [Google
Cloud](https://cloud.google.com/iam/docs/workload-identity-federation),
[AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction_access-management.html#intro-access-roles)
and
[Azure](https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview?view=graph-rest-1.0)
from any OIDC identity provider.

The [jwt.io](https://jwt.io/) and [jwt.ms](https://jwt.ms/) tools allow validating OIDC
id tokens without first configuring public keys by means of the [OpenID connect
discovery][oidc-discovery] protocol.

This library implements the OpenID Connect discovery standard in Python to allow
verification of OpenID Connect id tokens without previous configuration of public keys,
etc.

Both synchronous and asynchronous (`asyncio`) implementations are provided.

[oidc]: https://openid.net/specs/openid-connect-core-1_0.html
[oidc-discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html

## Example

Suppose you created a [GitLab OIDC
token](https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html) as part of a
CI job to make an authenticated HTTP GET request to some service:

```yaml
# .gitlab-ci.yml within https://gitlab.com/my-group/my-project

job_with_id_token:
  id_tokens:
    ID_TOKEN:
      aud: https://my-service.example.com
  script:
    - curl -X GET -H "Authorization: Bearer $ID_TOKEN" https://my-service.example.com
```

The following example shows how to verify the OIDC token came from a specific project
within a backend implementation:

```py
from typing import Any
from federatedidentity import Issuer, verifiers, verify_id_token

# Use OIDC discovery to fetch public keys for verifying GitLab tokens.
GITLAB_ISSUER = Issuer.from_discovery("https://gitlab.com")

# Expected project path for id token
EXPECTED_PROJECT_PATH = "my-group/my-project"

# Expected audience claim for id token.
EXPECTED_AUDIENCE_CLAIM = "https://my-service.example.com"

def verify_gitlab_token(token: str) -> dict[str, Any]:
    """
    Verify an OIDC token from GitLab and return the dictionary of claims. Raises
    federatedidentity.exceptions.FederatedIdentityError if the token failed verification.
    """
    return verify_id_token(
        token,
        valid_issuers=[GITLAB_ISSUER],
        valid_audiences=[EXPECTED_AUDIENCE_CLAIM],
        required_claims=[
            # The "project_path" claim must match the expected project.
            {"project_path": EXPECTED_PROJECT_PATH},
        ],
    )
```

See [the full documentation](https://rjw57.github.io/verify-oidc-identity/) for more
examples.
