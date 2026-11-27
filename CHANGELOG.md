# Changelog

## 0.1.1

- README links point at GitHub, so they work on the PyPI page too
- SECURITY.md has a direct link for private reports and says how disclosure works
- CI also audits the GitHub workflows with zizmor

## 0.1.0

The first release.

- Provider presets that strip credential headers, query parameters and OAuth body fields
- Secret rules in a JSON file, with a scanner that checks every part of every interaction, compressed bodies included
- Credentials safetape strips, and environment variables named like secrets, are looked for by exact value anywhere in a cassette, which catches keys with no recognisable shape
- `SafePersister`, which refuses to write a cassette that still looks like it has a secret in it, and writes atomically as UTF-8, with a few retries when Windows has the file locked
- A readable JSON serializer that stores JSON bodies as JSON and streamed responses as events
- Matchers that ignore stripped credentials, compare JSON by value and show a masked diff when nothing matches
- vcrpy's "can't play back" error and pytest's failure reports are masked, since both can show the live request
- Lockdown mode, on by default in CI, that never records
- A report of cassettes older than 90 days
- A pytest plugin that sets all of this up for pytest-recording
- Tested with the OpenAI and Anthropic Python SDKs, sync, async and streaming
