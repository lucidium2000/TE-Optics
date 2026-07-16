#!/usr/bin/env python3
"""Deploy AI provider API tests to ThousandEyes via v7 REST API."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Any

MATH_PROMPT = "What is 15 multiplied by 7? Reply with only the number."

AGENT_IDS = ["8641", "66", "59220", "675631", "55863", "56025", "26", "834471", "63"]

COMMON_TEST = {
    "interval": 300,
    "enabled": True,
    "alertsEnabled": True,
    "bgpMeasurements": True,
    "usePublicBgp": True,
    "networkMeasurements": True,
    "mtuMeasurements": True,
    "numPathTraces": 3,
    "pathTraceMode": "in-session",
    "probeMode": "auto",
    "protocol": "tcp",
    "randomizedStartTime": True,
    "targetTime": 25,
    "timeLimit": 60,
    "agents": [{"agentId": aid} for aid in AGENT_IDS],
}


def load_token() -> str:
    raw = open("/Users/chunt2/.cursor/mcp.json").read()
    m = re.search(r"Bearer\s+([^\"\}]+)", raw)
    if not m:
        sys.exit("Could not read TE API token from mcp.json")
    return m.group(1).strip()


def te_headers(step: int, extra: list[dict[str, str]] | None = None) -> list[dict[str, str]]:
    headers = [
        {"key": "x-thousandeyes-api-step-level", "value": str(step)},
        {"key": "x-thousandeyes-agent", "value": "yes"},
        {"key": "User-Agent", "value": "ThousandEyes"},
        {"key": "Accept", "value": "application/json"},
        {"key": "Accept-Encoding", "value": "gzip, deflate, br"},
        {"key": "Connection", "value": "keep-alive"},
    ]
    if extra:
        headers.extend(extra)
    return headers


def status_assert() -> list[dict[str, str]]:
    return [{"name": "status-code", "operator": "is", "value": "200"}]


def body_assert(value: str, operator: str = "includes") -> dict[str, str]:
    return {"name": "response-body", "operator": operator, "value": value}


def api_request(
    *,
    name: str,
    method: str,
    url: str,
    step: int,
    auth_type: str = "bearer-token",
    body: str | None = None,
    extra_headers: list[dict[str, str]] | None = None,
    assertions: list[dict[str, str]] | None = None,
    collect: bool = True,
    wait_ms: int = 0,
) -> dict[str, Any]:
    req: dict[str, Any] = {
        "name": name,
        "method": method,
        "url": url,
        "authType": auth_type,
        "collectApiResponse": collect,
        "verifyCertificate": True,
        "headers": te_headers(step, extra_headers),
        "assertions": assertions or status_assert(),
    }
    if body is not None:
        req["body"] = body
    if wait_ms:
        req["waitTimeMs"] = wait_ms
    return req


def openai_requests() -> list[dict[str, Any]]:
    monitor = [
        {"key": "X-TE-Monitor-Response-Headers", "value": "x-ratelimit-limit-tokens,x-ratelimit-remaining-tokens,x-ratelimit-reset-tokens,x-ratelimit-limit-requests,x-ratelimit-remaining-requests,openai-processing-ms,x-request-id"},
    ]
    chat_body = json.dumps(
        {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": MATH_PROMPT}],
            "max_tokens": 16,
            "temperature": 0,
        },
        separators=(",", ":"),
    )
    count_body = json.dumps(
        {"model": "gpt-4o-mini", "input": MATH_PROMPT},
        separators=(",", ":"),
    )
    return [
        api_request(
            name="Navigate to OpenAI",
            method="get",
            url="https://api.openai.com/v1/models",
            step=1,
            extra_headers=monitor,
        ),
        api_request(
            name="Page Load Complete",
            method="get",
            url="https://api.openai.com/v1/models/gpt-4o-mini",
            step=2,
            extra_headers=monitor,
            assertions=status_assert() + [body_assert("gpt-4o-mini")],
        ),
        api_request(
            name="Enter Math Prompt",
            method="post",
            url="https://api.openai.com/v1/responses/input_tokens",
            step=3,
            body=count_body,
            extra_headers=monitor + [{"key": "Content-Type", "value": "application/json"}],
            assertions=status_assert() + [body_assert("input_tokens")],
        ),
        api_request(
            name="Submit Math Prompt",
            method="post",
            url="https://api.openai.com/v1/chat/completions",
            step=4,
            body=chat_body,
            extra_headers=monitor + [{"key": "Content-Type", "value": "application/json"}],
            assertions=status_assert(),
        ),
        api_request(
            name="Wait for Response",
            method="get",
            url="https://api.openai.com/v1/models",
            step=5,
            extra_headers=monitor,
            assertions=status_assert(),
            collect=True,
        ),
        api_request(
            name="Response Received",
            method="post",
            url="https://api.openai.com/v1/chat/completions",
            step=6,
            body=chat_body,
            extra_headers=monitor + [{"key": "Content-Type", "value": "application/json"}],
            assertions=status_assert()
            + [
                body_assert("105"),
                body_assert("usage"),
                body_assert("total_tokens"),
            ],
        ),
    ]


def anthropic_requests() -> list[dict[str, Any]]:
    auth_headers = [
        {"key": "x-api-key", "value": "{{ANTHROPIC_API_KEY}}"},
        {"key": "anthropic-version", "value": "2023-06-01"},
        {
            "key": "X-TE-Monitor-Response-Headers",
            "value": "anthropic-ratelimit-tokens-limit,anthropic-ratelimit-tokens-remaining,anthropic-ratelimit-tokens-reset,anthropic-ratelimit-input-tokens-remaining,anthropic-ratelimit-output-tokens-remaining,anthropic-ratelimit-requests-limit,anthropic-ratelimit-requests-remaining,request-id,retry-after",
        },
    ]
    msg = json.dumps(
        {
            "model": "claude-3-5-haiku-20241022",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": MATH_PROMPT}],
        },
        separators=(",", ":"),
    )
    count_body = json.dumps(
        {
            "model": "claude-3-5-haiku-20241022",
            "messages": [{"role": "user", "content": MATH_PROMPT}],
        },
        separators=(",", ":"),
    )
    return [
        api_request(
            name="Navigate to Claude",
            method="get",
            url="https://api.anthropic.com/v1/models",
            step=1,
            auth_type="none",
            extra_headers=auth_headers,
        ),
        api_request(
            name="Page Load Complete",
            method="get",
            url="https://api.anthropic.com/v1/models",
            step=2,
            auth_type="none",
            extra_headers=auth_headers,
            assertions=status_assert() + [body_assert("claude")],
        ),
        api_request(
            name="Enter Math Prompt",
            method="post",
            url="https://api.anthropic.com/v1/messages/count_tokens",
            step=3,
            auth_type="none",
            body=count_body,
            extra_headers=auth_headers + [{"key": "Content-Type", "value": "application/json"}],
            assertions=status_assert() + [body_assert("input_tokens")],
        ),
        api_request(
            name="Submit Math Prompt",
            method="post",
            url="https://api.anthropic.com/v1/messages",
            step=4,
            auth_type="none",
            body=msg,
            extra_headers=auth_headers + [{"key": "Content-Type", "value": "application/json"}],
            assertions=status_assert(),
        ),
        api_request(
            name="Wait for Response",
            method="post",
            url="https://api.anthropic.com/v1/messages",
            step=5,
            auth_type="none",
            body=msg,
            extra_headers=auth_headers + [{"key": "Content-Type", "value": "application/json"}],
            assertions=status_assert()
            + [
                body_assert("usage"),
                body_assert("input_tokens"),
                body_assert("output_tokens"),
            ],
        ),
        api_request(
            name="Response Received",
            method="post",
            url="https://api.anthropic.com/v1/messages",
            step=6,
            auth_type="none",
            body=msg,
            extra_headers=auth_headers + [{"key": "Content-Type", "value": "application/json"}],
            assertions=status_assert() + [body_assert("105")],
        ),
    ]


def gemini_requests() -> list[dict[str, Any]]:
    model = "gemini-2.0-flash"
    base = f"https://generativelanguage.googleapis.com/v1beta/models/{model}"
    auth_headers = [
        {"key": "x-goog-api-key", "value": "{{GEMINI_API_KEY}}"},
        {
            "key": "X-TE-Monitor-Response-Headers",
            "value": "x-goog-api-client,x-goog-request-params,usageMetadata(in-body),promptTokenCount,candidatesTokenCount,totalTokenCount",
        },
    ]
    contents = json.dumps(
        {"contents": [{"parts": [{"text": MATH_PROMPT}]}]},
        separators=(",", ":"),
    )
    gen_body = json.dumps(
        {
            "contents": [{"parts": [{"text": MATH_PROMPT}]}],
            "generationConfig": {"maxOutputTokens": 16, "temperature": 0},
        },
        separators=(",", ":"),
    )
    return [
        api_request(
            name="Navigate to Gemini",
            method="get",
            url="https://generativelanguage.googleapis.com/v1beta/models",
            step=1,
            auth_type="none",
            extra_headers=auth_headers,
        ),
        api_request(
            name="Page Load Complete",
            method="get",
            url=base,
            step=2,
            auth_type="none",
            extra_headers=auth_headers,
            assertions=status_assert() + [body_assert(model)],
        ),
        api_request(
            name="Enter Math Prompt",
            method="post",
            url=f"{base}:countTokens",
            step=3,
            auth_type="none",
            body=contents,
            extra_headers=auth_headers + [{"key": "Content-Type", "value": "application/json"}],
            assertions=status_assert() + [body_assert("totalTokens")],
        ),
        api_request(
            name="Submit Math Prompt",
            method="post",
            url=f"{base}:generateContent",
            step=4,
            auth_type="none",
            body=gen_body,
            extra_headers=auth_headers + [{"key": "Content-Type", "value": "application/json"}],
            assertions=status_assert(),
        ),
        api_request(
            name="Wait for Response",
            method="post",
            url=f"{base}:generateContent",
            step=5,
            auth_type="none",
            body=gen_body,
            extra_headers=auth_headers + [{"key": "Content-Type", "value": "application/json"}],
            assertions=status_assert()
            + [
                body_assert("usageMetadata"),
                body_assert("promptTokenCount"),
                body_assert("candidatesTokenCount"),
                body_assert("totalTokenCount"),
            ],
        ),
        api_request(
            name="Response Received",
            method="post",
            url=f"{base}:generateContent",
            step=6,
            auth_type="none",
            body=gen_body,
            extra_headers=auth_headers + [{"key": "Content-Type", "value": "application/json"}],
            assertions=status_assert() + [body_assert("105")],
        ),
    ]


def te_api(token: str, method: str, path: str, payload: dict | None = None) -> dict:
    cmd = [
        "curl",
        "-sS",
        "-X",
        method,
        f"https://api.thousandeyes.com/v7{path}",
        "-H",
        f"Authorization: Bearer {token}",
        "-H",
        "Content-Type: application/json",
        "-H",
        "Accept: application/json",
    ]
    if payload is not None:
        cmd += ["-d", json.dumps(payload)]
    out = subprocess.check_output(cmd, text=True)
    if not out.strip():
        return {}
    return json.loads(out)


def main() -> None:
    token = load_token()

    tests = [
        {
            "action": "update",
            "test_id": "8869626",
            "payload": {
                **COMMON_TEST,
                "testName": "API - https://api.openai.com/ (OpenAI)",
                "url": "https://api.openai.com/v1/models",
                "requests": openai_requests(),
            },
        },
        {
            "action": "create",
            "payload": {
                **COMMON_TEST,
                "testName": "API - https://api.anthropic.com/ (Claude)",
                "url": "https://api.anthropic.com/v1/models",
                "requests": anthropic_requests(),
            },
        },
        {
            "action": "create",
            "payload": {
                **COMMON_TEST,
                "testName": "API - https://generativelanguage.googleapis.com/ (Gemini)",
                "url": "https://generativelanguage.googleapis.com/v1beta/models",
                "requests": gemini_requests(),
            },
        },
    ]

    for spec in tests:
        if spec["action"] == "update":
            result = te_api(token, "PUT", f"/tests/api/{spec['test_id']}", spec["payload"])
            print(f"UPDATED {spec['test_id']}: {result.get('testName')}")
        else:
            result = te_api(token, "POST", "/tests/api", spec["payload"])
            print(f"CREATED {result.get('testId')}: {result.get('testName')}")

    # Remove accidental instant probe from earlier MCP attempt
    try:
        te_api(token, "DELETE", "/tests/api/8869628")
        print("DELETED instant probe 8869628")
    except subprocess.CalledProcessError:
        pass

    # Verify first request on OpenAI test
    verify = te_api(token, "GET", "/tests/api/8869626?expand=agent")
    req0 = verify["requests"][0]
    print(
        "VERIFY OpenAI step1:",
        req0.get("authType"),
        req0.get("collectApiResponse"),
        len(req0.get("assertions", [])),
        "agents=",
        len(verify.get("agents") or []),
    )


if __name__ == "__main__":
    main()
