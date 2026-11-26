# Threat model

This is a living document. It gets updated whenever a feature changes what safetape touches.

## What safetape is for

Tests record real HTTP calls to LLM providers into cassette files, and those files usually get committed. safetape's job is to make sure nothing secret goes into them.

## What we're protecting

- API keys, tokens, cookies and signed credentials that travel in HTTP requests and responses
- Secrets that show up inside request or response bodies (a key pasted into a prompt, a token echoed back in an error)
- The machine that loads a cassette, which may come from someone else's pull request

## Who or what could cause harm

- **The developer by accident.** This is by far the most likely case: a new header, a new provider, a key in a prompt.
- **A provider SDK update** that adds or renames a header carrying credentials.
- **A malicious cassette** submitted in a pull request, built to run code or read files when a test loads it.
- **A supply chain attack** on safetape itself: a hijacked dependency, a tampered release or a compromised CI workflow.

## Threats and what we do about them

| Threat | Mitigation |
|---|---|
| A credential header gets recorded | Provider presets strip known headers and query params by default. The list is tested against each supported provider. |
| A secret sits in a body or an unknown header | Every cassette is scanned with pattern rules plus entropy checks just before it's written to disk. |
| The scan misses something and the file gets written anyway | The writer fails closed. If the scan reports anything, nothing is written and the test fails with the location (the value itself is masked in the error). |
| A cassette is half written after a crash | Cassettes are written to a temporary file and moved into place, so a file is either the old version or the complete new one. |
| Text is garbled on Windows | Files are always read and written as UTF-8, never with the platform default encoding. |
| A malicious cassette runs code on load | safetape requires vcrpy 8.2.1 or newer, which loads YAML with a safe loader (GHSA-rpj2-4hq8-938g). Any loader safetape adds will never construct arbitrary Python objects. |
| An error message or log leaks the secret it found | Findings only show the rule name, the location and a masked preview. |
| Supply chain | No runtime dependencies besides vcrpy. Dev dependencies are locked with hashes. GitHub Actions are pinned to commit SHAs with read-only permissions by default. CodeQL, gitleaks, pip-audit and OpenSSF Scorecard run in CI. Releases will be published with PyPI trusted publishing, so no long-lived token exists. |

## Out of scope

- Secrets that are already in your git history. Rotate them, then clean history with a tool built for that.
- Secrets in formats with no recognisable structure and low entropy, like a short password in plain prose. Detection can't be perfect, so GitHub secret scanning should stay on as well.
- Protecting a cassette from someone who can already change your test code.
