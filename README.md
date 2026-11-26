# safetape

Record your LLM API calls once, replay them in tests, and stop worrying about committing an API key by accident.

safetape sits on top of [vcrpy](https://github.com/kevin1024/vcrpy) and [pytest-recording](https://github.com/kiwicom/pytest-recording). It knows what OpenAI, Anthropic, Gemini and other provider traffic looks like, so it can strip credentials before a cassette is written and refuse to save one that still has a secret in it.

**Status: early.** Nothing is on PyPI yet. This README describes where it's going.

## Why I'm building this

If you test code that calls an LLM API you've probably been here. Live calls in tests are slow, cost money and give a different answer every run, so you record them with vcrpy. Then you find out vcrpy has no idea which headers or body fields are secret, so you write your own filters. Then a provider SDK adds a header you didn't think of and a key ends up in git.

A lot of projects have written their own version of this glue code. I wanted one place where it's done once, with safe defaults instead of opt-in settings.

## Plan for v0.1

- Strip auth headers and query params for the common providers out of the box (OpenAI, Anthropic, Gemini, Azure OpenAI, Mistral, Groq, OpenRouter, AWS Bedrock and others)
- Scan request and response bodies for anything that looks like a secret
- Refuse to write a cassette that still has something secret-looking in it, and point to where it is
- Store JSON and streaming (SSE) bodies in a readable way so cassette diffs make sense in review
- Match requests while ignoring fields that change on every run
- A CI mode that never touches the network and shows a diff when a recording is missing
- Warn when cassettes get old

## What it can't promise

Detection is pattern based, so a key in an unusual format can still slip through. Use it as a safety net on top of secret scanning in your repo, not instead of it, and rotate anything that leaks.

## Security

See [SECURITY.md](SECURITY.md) for how to report a problem, and [docs/threat-model.md](docs/threat-model.md) for what this project tries to protect against.

## License

MIT
