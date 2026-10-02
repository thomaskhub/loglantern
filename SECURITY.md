# Security

Please report vulnerabilities privately through GitHub's
[security advisories](https://github.com/thomkin/loglantern/security/advisories/new), not in public issues.
You will get an answer within a week.

Deployment notes:
- Keep the ingest port on a private network.
- Put the API behind TLS.
- Give API keys the lowest role they need.
- Data sent to AI agents is masked, but it still leaves your server; leave `ai` out if that is not acceptable.
