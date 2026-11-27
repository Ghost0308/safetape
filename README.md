# safetape

Record your LLM API calls once, replay them in tests, and stop worrying about committing an API key by accident.

safetape sits on top of [vcrpy](https://github.com/kevin1024/vcrpy) and [pytest-recording](https://github.com/kiwicom/pytest-recording). It knows what OpenAI, Anthropic, Gemini and other provider traffic looks like, so it strips credentials before a cassette is written and refuses to save one that still has a secret in it.

**Status: early.** This is 0.1, so expect things to change. It needs Python 3.11 or newer and vcrpy 8.2.1 or newer.

```
pip install safetape
```

It's tested with the OpenAI and Anthropic Python SDKs (sync, async and streaming), which send their requests through httpx2. vcrpy patches that as well as httpx, requests, aiohttp and the other usual clients.

## Why I'm building this

If you test code that calls an LLM API you've probably been here. Live calls in tests are slow, cost money and give a different answer every run, so you record them with vcrpy. Then you find out vcrpy has no idea which headers or body fields are secret, so you write your own filters. Then a provider SDK adds a header you didn't think of and a key ends up in git.

A lot of projects have written their own version of this glue code. I wanted one place where it's done once, with safe defaults instead of opt-in settings.

## With pytest-recording

Install safetape next to pytest-recording and you're done. Its pytest plugin switches on by itself for every `@pytest.mark.vcr` test.

```python
import pytest
from openai import OpenAI


@pytest.mark.vcr
def test_capital() -> None:
    reply = OpenAI().responses.create(model="gpt-5-mini", input="Capital of France?")
    assert "Paris" in reply.output_text
```

Record once with `pytest --record-mode=once`, then commit the cassettes. I'd also switch pytest-recording to JSON so the cassettes are easy to read (more on that below):

```python
# conftest.py
@pytest.fixture(scope="module")
def vcr_config():
    return {"serializer": "json"}
```

## With plain vcrpy

```python
import vcr
import safetape

my_vcr = safetape.install(vcr.VCR(cassette_library_dir="tests/cassettes", serializer="json"))

with my_vcr.use_cassette("capital.json"):
    ...
```

## What happens before a cassette is saved

safetape drops credential headers like `authorization`, `x-api-key`, `x-goog-api-key`, `api-key`, `openai-organization`, `cookie` and `set-cookie`, and credential query parameters like Gemini's `?key=` and the signature on AWS presigned URLs. In JSON and form bodies it replaces fields like `access_token`, `refresh_token` and `client_secret` with `REDACTED`, which covers OAuth token exchanges such as the ones Vertex AI does behind your back.

Then it scans everything that's left, compressed bodies included, for anything that looks like a key or token. Some providers (Mistral, Cohere, Azure OpenAI) use keys with no recognisable shape, so it also looks for exact values it already knows are secret: the credentials it just stripped, and the values of environment variables with names like `MISTRAL_API_KEY`. That's how a key pasted into a prompt or echoed back in an error still gets caught, whatever it looks like.

If it finds something, nothing is written and the test fails with the location. The error shows the rule and a masked preview, never the value:

```
safetape didn't save tests/cassettes/test_capital.json because it still has something that looks like a secret:

  interaction 1, response body: OpenAI project, service account or admin key [openai-key] sk-p... (164 chars)
```

All of this happens whichever provider a cassette talks to. The per-provider lists are in [_presets.py](https://github.com/Ghost0308/safetape/blob/main/src/safetape/_presets.py) and the secret rules are in [rules.json](https://github.com/Ghost0308/safetape/blob/main/src/safetape/rules.json). The rules file is plain JSON with regexes that Python and JavaScript read the same way, so other tools can use it too.

## Readable cassettes

vcrpy stores every body as one long string. With the `json` serializer, safetape stores JSON bodies as JSON, streamed responses as a list of events, and binary bodies as base64. A re-recorded cassette then gives you a diff you can actually review:

```json
"body": {
  "sse": [
    {"event": "content_block_delta", "data": {"type": "content_block_delta", "delta": {"text": "Hi"}}},
    {"event": "message_stop", "data": {"type": "message_stop"}}
  ]
}
```

It still reads cassettes written by vcrpy's own JSON serializer. On replay the JSON is encoded again, compactly, so the bytes can differ from what the server sent even though the data is the same. Content-Length is updated to match. If a test compares raw response bytes, stay on YAML.

## Matching requests

Almost every LLM call is a POST to the same path, so vcrpy's default matching can't tell two prompts apart and just replays answers in the order they were recorded. safetape adds `body` to `match_on`, unless you've set `match_on` yourself.

It also replaces vcrpy's `query`, `uri` and `body` matchers. They ignore the credentials it strips, so a cassette recorded with one key still replays with another. The body matcher compares JSON by value, so key order and whitespace don't matter, ignores the random boundary in multipart uploads, and can skip fields that change on every run, like `metadata.user_id` or `messages.*.id`.

When nothing matches, vcrpy's error includes a diff of the bodies with any secrets masked.

## Lockdown in CI

When the `CI` environment variable is set, safetape never records. Whatever record mode a test asks for, requests are only replayed, and a request with no recording fails the test without touching the network. Set `SAFETAPE_LOCKDOWN=0` or `safetape_lockdown = off` if you really do want to record in CI.

## Old cassettes

At the end of a run, safetape lists cassettes whose responses are more than 90 days old, going by their `Date` headers. Providers change their APIs often enough that an old cassette can keep a test green long after the real thing broke. With plain vcrpy you get a `StaleCassetteWarning` when an old cassette loads.

## Settings

Everything adds to the defaults. There's no way to switch a default off, so a typo can't quietly stop a header from being stripped.

```toml
[tool.pytest.ini_options]
safetape_redact_headers = ["x-corp-auth"]
safetape_redact_query_params = ["sig2"]
safetape_redact_body_fields = ["session_secret"]
safetape_allow = ["^sk-test-"]  # regexes for values that look secret but aren't
safetape_rules = ["tests/more-rules.json"]
safetape_ignore_body_fields = ["metadata.user_id", "messages.*.id"]
safetape_stale_days = 90  # 0 turns the report off
safetape_lockdown = "auto"  # or "on" or "off"
```

With plain vcrpy, pass the same things to `safetape.install(my_vcr, safetape.Settings(...))`.

To turn the plugin off for a run, use `pytest -p no:safetape`.

## What it can't promise

Detection is pattern based, plus exact matches for the credentials it knows about. A key in an unusual format that isn't in a header or an environment variable can still slip through, and so can a known key that was encoded or split up on its way into a body. Use it as a safety net on top of secret scanning in your repo, not instead of it, and rotate anything that leaks.

When a test fails, the error and the frames pytest prints can describe the live request before it was scrubbed. The plugin masks secrets in pytest's failure reports and captured output, and vcrpy's "can't play back this request" error is masked wherever it's shown. Other tools that print local variables, like rich tracebacks or Sentry, are outside what safetape can see.

## Security

See [SECURITY.md](https://github.com/Ghost0308/safetape/blob/main/SECURITY.md) for how to report a problem, and [docs/threat-model.md](https://github.com/Ghost0308/safetape/blob/main/docs/threat-model.md) for what this project tries to protect against.

## License

MIT
