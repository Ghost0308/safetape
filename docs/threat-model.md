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
| A credential header gets recorded | Provider presets strip known headers and query params by default, for every provider at once. Settings can add to the list but never remove from it. |
| An OAuth or cloud credential exchange gets recorded | Known credential fields in JSON and form bodies (`access_token`, `refresh_token`, `client_secret` and similar) are replaced with `REDACTED`. |
| A secret sits in a body or an unknown header | Every interaction is scanned with pattern rules plus entropy checks just before it's written, and so is the final text the serializer produces. Headers with secret-sounding names and high-entropy values are flagged even without a matching rule. |
| A key with no recognisable shape gets copied somewhere (Mistral, Cohere and Azure OpenAI keys look like any random string) | safetape remembers the credentials it strips from headers, query parameters and body fields, and reads environment variables with secret-sounding names. It looks for those exact values everywhere in the cassette, across all of its interactions. |
| A failing test prints the live request | When a request has no recording, vcrpy's error and the frames pytest prints describe the live request before scrubbing. safetape masks vcrpy's error message when it's created, and the pytest plugin masks failure reports and captured output, using the pattern rules, the credential query parameter names and the credentials seen during the run. |
| A compressed body hides a secret from the scan | Bodies are decompressed before scanning. A body safetape can't decompress, or one over 256 MB once decompressed, counts as a finding, so it isn't saved. |
| The scan misses something and the file gets written anyway | The writer fails closed. If the scan reports anything, nothing is written and the test fails with the location (the value itself is masked in the error). |
| The error about a secret prints the secret | Findings only show the rule name, the location and a masked preview. pytest prints function arguments in long tracebacks, and the frames that saved the cassette hold it before scrubbing, so safetape raises its errors with a fresh traceback that starts above those frames. |
| A failed save leaves vcrpy's HTTP patches in place | vcrpy removes its patches only after a successful save, so a refused save would leave them active and later tests could talk to the network or the wrong cassette. safetape makes vcrpy remove them either way. `SafePersister` applies this itself, so it holds with or without `install()`. |
| A file can't be replaced because Windows has it locked for a moment | The final rename gets a few tries with a short wait in between. The temporary file is removed if it never works. |
| CI records new cassettes with real credentials | Lockdown is on by default when `CI` is set. Every cassette is forced to record mode `none`, so a missing recording fails without a network call, and the persister refuses to write anything new. |
| A cassette is half written after a crash | Cassettes are written to a temporary file and moved into place, so a file is either the old version or the complete new one. |
| Text is garbled on Windows | Files are always read and written as UTF-8 with Unix line endings, never with the platform default encoding. |
| A malicious cassette runs code on load | safetape requires vcrpy 8.2.1 or newer, which loads YAML with a safe loader (GHSA-rpj2-4hq8-938g). safetape's JSON serializer only ever builds plain data. |
| Supply chain | No runtime dependencies besides vcrpy. Dev dependencies are locked with hashes. GitHub Actions are pinned to commit SHAs with read-only permissions by default. CodeQL, gitleaks, pip-audit and OpenSSF Scorecard run in CI. Releases will be published with PyPI trusted publishing, so no long-lived token exists. |

## Known gaps

- Exact-value matching only finds exact copies. A known key that was base64 encoded, split across chunks or otherwise changed on its way into a body won't match, and a shapeless key that never passed through a header or an environment variable isn't known at all.
- Outside pytest, tools that print local variables in tracebacks (rich, Sentry and similar) can still show the live request. Only vcrpy's own error message is masked there.
- The vcrpy fixes change vcrpy's classes for the whole process once safetape is used. They only act when something goes wrong, but other code that relies on the old behaviour would see the change.

## Out of scope

- Secrets that are already in your git history. Rotate them, then clean history with a tool built for that.
- Secrets in formats with no recognisable structure and low entropy, like a short password in plain prose. Detection can't be perfect, so GitHub secret scanning should stay on as well.
- Protecting a cassette from someone who can already change your test code or your rules file.
