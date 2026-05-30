"""
Demonstrates using CodexChatModel with LangChain and LangGraph.

Run with:
    uv run python tests/live/codex_langgraph_demo.py
"""

import sys
from typing import TypedDict

import httpx
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph

from codex_device_auth.codex_chat_model import CodexChatModel
from codex_device_auth.config import credential_path
from codex_device_auth.credentials import load_credentials


def main() -> int:
    credential = load_credentials(credential_path())
    if credential is None:
        print("not logged in — run 'uv run openai-auth login' first", file=sys.stderr)
        return 1

    with httpx.Client() as client:
        model = CodexChatModel(credential=credential, client=client)

        # --- 1. Basic invoke ---
        print("=== 1. Basic invoke ===")
        response = model.invoke([HumanMessage(content="What is 2 + 2? Answer in one sentence.")])
        print(response.content)
        print()

        # --- 2. Multi-turn with system prompt ---
        print("=== 2. System prompt + multi-turn ===")
        messages = [
            SystemMessage(content="You are a pirate. Always respond in pirate speak."),
            HumanMessage(content="What is the capital of France?"),
        ]
        response = model.invoke(messages)
        print(response.content)
        print()

        # --- 3. Streaming ---
        print("=== 3. Streaming ===")
        for chunk in model.stream(
            [HumanMessage(content="Count from 1 to 5, one number per line.")]
        ):
            print(chunk.content, end="", flush=True)
        print("\n")

        # --- 4. LangGraph workflow ---
        print("=== 4. LangGraph workflow ===")

        class State(TypedDict):
            messages: list[BaseMessage]

        def call_model(state: State) -> State:
            response = model.invoke(state["messages"])
            return {"messages": [*state["messages"], response]}

        builder = StateGraph(State)
        builder.add_node("model", call_model)
        builder.set_entry_point("model")
        builder.add_edge("model", END)
        graph = builder.compile()

        result = graph.invoke(
            {
                "messages": [
                    HumanMessage(
                        content="Name three programming languages in a comma-separated list."
                    )
                ]
            }
        )
        final_message = result["messages"][-1]
        print(f"Graph output: {final_message.content}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
