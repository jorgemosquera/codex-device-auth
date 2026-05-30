import json
from typing import Any, Iterator

import httpx
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    BaseMessage,
    HumanMessage,
    SystemMessage,
)
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult
from pydantic import PrivateAttr

from codex_device_auth.config import (
    CODEX_MODEL,
    CODEX_RESPONSES_URL,
    PROVIDER_ORIGINATOR,
    PROVIDER_USER_AGENT,
)
from codex_device_auth.credentials import Credential, redact_secrets
from codex_device_auth.errors import RuntimeRequestError


class CodexChatModel(BaseChatModel):
    """LangChain chat model backed by the OpenAI Codex Responses endpoint.

    Supports invoke() and stream(). SystemMessage maps to the instructions
    field; HumanMessage and AIMessage map to user/assistant turns.
    """

    model: str = CODEX_MODEL
    request_timeout: float = 60.0

    _credential: Credential = PrivateAttr()
    _client: httpx.Client = PrivateAttr()

    def __init__(self, *, credential: Credential, client: httpx.Client, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._credential = credential
        self._client = client

    @property
    def _llm_type(self) -> str:
        return "openai-codex"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        instructions, input_messages = _convert_messages(messages)
        text = _call_codex(
            self._client,
            self._credential,
            instructions,
            input_messages,
            self.model,
            self.request_timeout,
        )
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=text))])

    def _stream(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> Iterator[ChatGenerationChunk]:
        instructions, input_messages = _convert_messages(messages)
        headers = _build_headers(self._credential)
        body = _build_body(instructions, input_messages, self.model)

        with self._client.stream(
            "POST", CODEX_RESPONSES_URL, headers=headers, json=body, timeout=self.request_timeout
        ) as response:
            if response.status_code >= 300:
                raise RuntimeRequestError(
                    redact_secrets(
                        f"codex request rejected with HTTP {response.status_code}",
                        self._credential,
                    )
                )
            for line in response.iter_lines():
                if not line.startswith("data: "):
                    continue
                payload = line[6:]
                if payload == "[DONE]":
                    break
                try:
                    event = json.loads(payload)
                except ValueError:
                    continue
                if event.get("type") == "response.output_text.delta":
                    delta = event.get("delta", "")
                    if isinstance(delta, str) and delta:
                        chunk = ChatGenerationChunk(message=AIMessageChunk(content=delta))
                        if run_manager:
                            run_manager.on_llm_new_token(delta)
                        yield chunk


def _convert_messages(messages: list[BaseMessage]) -> tuple[str, list[dict]]:
    instructions = "You are a helpful assistant."
    input_messages = []
    for msg in messages:
        if isinstance(msg, SystemMessage):
            instructions = str(msg.content)
        elif isinstance(msg, HumanMessage):
            input_messages.append(
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": str(msg.content)}],
                }
            )
        elif isinstance(msg, AIMessage):
            input_messages.append(
                {
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": str(msg.content)}],
                }
            )
    return instructions, input_messages


def _build_headers(credential: Credential) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {credential.access_token}",
        "originator": PROVIDER_ORIGINATOR,
        "User-Agent": PROVIDER_USER_AGENT,
        "content-type": "application/json",
        "OpenAI-Beta": "responses=experimental",
        "accept": "text/event-stream",
    }
    if credential.account_id:
        headers["chatgpt-account-id"] = credential.account_id
    return headers


def _build_body(instructions: str, input_messages: list[dict], model: str) -> dict:
    return {
        "model": model,
        "store": False,
        "stream": True,
        "instructions": instructions,
        "input": input_messages,
        "text": {"verbosity": "low"},
        "include": ["reasoning.encrypted_content"],
        "tool_choice": "auto",
        "parallel_tool_calls": True,
    }


def _call_codex(
    client: httpx.Client,
    credential: Credential,
    instructions: str,
    input_messages: list[dict],
    model: str,
    timeout: float,
) -> str:
    headers = _build_headers(credential)
    body = _build_body(instructions, input_messages, model)
    text_parts: list[str] = []

    with client.stream(
        "POST", CODEX_RESPONSES_URL, headers=headers, json=body, timeout=timeout
    ) as response:
        if response.status_code >= 300:
            raise RuntimeRequestError(
                redact_secrets(
                    f"codex request rejected with HTTP {response.status_code}", credential
                )
            )
        for line in response.iter_lines():
            if not line.startswith("data: "):
                continue
            payload = line[6:]
            if payload == "[DONE]":
                break
            try:
                event = json.loads(payload)
            except ValueError:
                continue
            if event.get("type") == "response.output_text.delta":
                delta = event.get("delta", "")
                if isinstance(delta, str):
                    text_parts.append(delta)

    result = "".join(text_parts)
    if not result:
        raise RuntimeRequestError("codex response contained no text")
    return redact_secrets(result, credential)
