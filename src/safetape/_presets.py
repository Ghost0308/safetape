"""What each provider uses to carry credentials.

safetape strips all of these by default, whichever provider a cassette talks to.
Keeping them per provider makes the list easy to check against each provider's docs.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Preset:
    name: str
    request_headers: frozenset[str] = field(default_factory=frozenset)
    response_headers: frozenset[str] = field(default_factory=frozenset)
    query_params: frozenset[str] = field(default_factory=frozenset)


def _preset(
    name: str,
    request_headers: tuple[str, ...] = (),
    response_headers: tuple[str, ...] = (),
    query_params: tuple[str, ...] = (),
) -> Preset:
    return Preset(
        name,
        frozenset(h.lower() for h in request_headers),
        frozenset(h.lower() for h in response_headers),
        frozenset(q.lower() for q in query_params),
    )


PRESETS: dict[str, Preset] = {
    preset.name: preset
    for preset in (
        _preset(
            "common",
            request_headers=(
                "authorization",
                "proxy-authorization",
                "cookie",
                "x-api-key",
                "api-key",
                "x-auth-token",
            ),
            response_headers=("set-cookie", "set-cookie2"),
            query_params=("api_key", "api-key", "apikey", "access_token", "token", "client_secret"),
        ),
        _preset(
            "openai",
            request_headers=("authorization", "openai-organization", "openai-project"),
            response_headers=("openai-organization", "openai-project", "set-cookie"),
        ),
        _preset(
            "anthropic",
            request_headers=("x-api-key", "authorization"),
            response_headers=("anthropic-organization-id",),
        ),
        _preset(
            "gemini",
            request_headers=("x-goog-api-key", "authorization"),
            query_params=("key",),
        ),
        _preset("vertex-ai", request_headers=("authorization", "x-goog-user-project")),
        _preset("azure-openai", request_headers=("api-key", "authorization")),
        _preset(
            "aws-bedrock",
            request_headers=("authorization", "x-amz-security-token"),
            query_params=("x-amz-credential", "x-amz-signature", "x-amz-security-token"),
        ),
        _preset("mistral", request_headers=("authorization",)),
        _preset("groq", request_headers=("authorization",), response_headers=("set-cookie",)),
        _preset("openrouter", request_headers=("authorization",)),
        _preset("cohere", request_headers=("authorization",)),
        _preset("deepseek", request_headers=("authorization",)),
        _preset("xai", request_headers=("authorization",)),
        _preset("together", request_headers=("authorization",)),
        _preset("fireworks", request_headers=("authorization",)),
        _preset("perplexity", request_headers=("authorization",)),
        _preset("huggingface", request_headers=("authorization",)),
        _preset("replicate", request_headers=("authorization",)),
        _preset("azure-storage", query_params=("sig",)),
    )
}

# Fields in JSON and form bodies whose values are credentials, compared after
# lower-casing and dropping "_" and "-". OAuth token exchanges and cloud
# credential endpoints send these.
BODY_FIELDS = frozenset(
    {
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "clientsecret",
        "apikey",
        "secretaccesskey",
        "sessiontoken",
    },
)


def default_request_headers() -> frozenset[str]:
    return frozenset().union(*(p.request_headers for p in PRESETS.values()))


def default_response_headers() -> frozenset[str]:
    return frozenset().union(*(p.response_headers for p in PRESETS.values()))


def default_query_params() -> frozenset[str]:
    return frozenset().union(*(p.query_params for p in PRESETS.values()))


def normalize_field(name: str) -> str:
    return name.lower().replace("_", "").replace("-", "")
