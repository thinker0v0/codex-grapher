# Security

This experimental project has no production support commitment or certified
deployment. Its broader operational release verdict is `NOT_PASS`. Deterministic
fixtures use no real platform, model or channel credentials. Real repository
tasks use the separately configured provider account described in the
[workflow guide](docs/REPOSITORY_WORKFLOW.md).

The Linux bootstrap is trusted root code. Its four dropped roles protect
integration state and the signing key from workers and candidate tests. The
provider's own login is available to its worker identity, including commands
launched under that identity; isolation from that login is not claimed.
Candidate-test and signer roles receive no provider authentication. Keep private
keys and login stores outside repositories, artifacts and workspace backups.

For a sensitive vulnerability, use GitHub's **Security → Report a vulnerability**
for this repository if the owner has enabled private vulnerability reporting.
If that option is unavailable, open a public issue asking the maintainer to enable
private reporting, without disclosing exploit details or sensitive data. No
separate security email address or response-time promise is provided.

Never include credentials, private configuration, personal data, or unpublished
financial information in an issue, pull request, attachment, or test fixture.
Provide a minimal secret-free reproduction, affected commit, expected boundary,
and observed behavior through the private reporting channel when available.
