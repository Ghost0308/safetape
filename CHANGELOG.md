# Changelog

## Unreleased

- Project setup: packaging, CI and security checks and docs
- Secret rules in a JSON file, with a scanner that checks every part of every interaction, compressed bodies included
- Credentials safetape strips, and environment variables named like secrets, are looked for by exact value anywhere in a cassette, which catches keys with no recognisable shape
- vcrpy's "can't play back" error and pytest's failure reports are masked, since both can show the live request
- Provider presets that strip credential headers, query parameters and OAuth body fields
- `SafePersister`, which refuses to write a cassette that still looks like it has a secret in it, and writes atomically as UTF-8, with a few retries when Windows has the file locked
- A readable JSON serializer that stores JSON bodies as JSON and streamed responses as events
- Matchers that ignore stripped credentials, compare JSON by value and show a masked diff when nothing matches
- Lockdown mode, on by default in CI, that never records
- A report of cassettes older than 90 days
- A pytest plugin that sets all of this up for pytest-recording
