"""Moon mission planner. The mod revalidates every proposal; nothing here grants rewards or progress."""

import json
import logging
import os
import re
from collections.abc import Callable
from typing import Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger("mars-planner")
KEY = r"^[a-z0-9_]{1,64}$"
CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class Need(BaseModel):
    model_config = ConfigDict(extra="forbid")
    template: str = Field(pattern=KEY)
    item: str = Field(pattern=r"^[a-z0-9_.-]+:[a-z0-9/._-]+$", max_length=200)
    remaining: int = Field(ge=1, le=1_000_000)
    chunk: int = Field(ge=1, le=4096)


class PlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    phase: str = Field(pattern=KEY)
    needs: list[Need] = Field(min_length=1, max_length=32)
    recent: list[str] = Field(default_factory=list, max_length=16)
    readyPlayers: int = Field(default=0, ge=0, le=1000)


class Proposal(BaseModel):
    template: str
    quantity: int
    briefing: str | None = None


class PlanResponse(BaseModel):
    proposal: Proposal
    source: Literal["model", "heuristic"]


ModelCall = Callable[[PlanRequest], dict | None]


def heuristic(request: PlanRequest) -> Proposal:
    need = min(request.needs, key=lambda value: (-value.remaining, value.template))
    return Proposal(template=need.template, quantity=min(need.remaining, need.chunk))


def checked(request: PlanRequest, raw: object) -> Proposal | None:
    if not isinstance(raw, dict):
        return None
    template, quantity, briefing = (
        raw.get("template"),
        raw.get("quantity"),
        raw.get("briefing"),
    )
    need = next((value for value in request.needs if value.template == template), None)
    if (
        need is None
        or type(quantity) is not int
        or not 1 <= quantity <= min(need.remaining, need.chunk)
    ):
        return None
    if briefing is not None:
        if not isinstance(briefing, str):
            return None
        briefing = CONTROL.sub(" ", briefing).strip()
        if len(briefing) > 480:
            return None
    return Proposal(
        template=need.template, quantity=quantity, briefing=briefing or None
    )


def plan(request: PlanRequest, model: ModelCall | None) -> PlanResponse:
    if model is not None:
        try:
            proposal = checked(request, model(request))
        except Exception:  # noqa: BLE001
            logger.warning("planner_model_failed")
            proposal = None
        if proposal is not None:
            return PlanResponse(proposal=proposal, source="model")
    return PlanResponse(proposal=heuristic(request), source="heuristic")


class ChatModel:
    """OpenAI-compatible chat endpoint, for example a local llama.cpp server or Ollama."""

    def __init__(self, url: str, name: str, timeout: float):
        parts = urlsplit(url)
        if (
            parts.scheme not in ("http", "https")
            or not parts.netloc
            or parts.username
            or parts.password
        ):
            raise ValueError(
                "MARS_PLANNER_MODEL_URL must be an http(s) URL without credentials"
            )
        if not 0 < timeout <= 60 or not re.fullmatch(r"[A-Za-z0-9._:/-]{1,120}", name):
            raise ValueError("Invalid planner model name or timeout")
        self.url, self.name, self.timeout = (
            url.rstrip("/") + "/v1/chat/completions",
            name,
            timeout,
        )

    @classmethod
    def from_env(cls) -> "ChatModel | None":
        url = os.environ.get("MARS_PLANNER_MODEL_URL", "")
        if not url:
            return None
        return cls(
            url,
            os.environ.get("MARS_PLANNER_MODEL", "qwen2.5-0.5b-instruct"),
            float(os.environ.get("MARS_PLANNER_TIMEOUT_SECONDS", "5")),
        )

    def __call__(self, request: PlanRequest) -> dict | None:
        needs = "\n".join(
            f"- {n.template}: need {n.remaining} x {n.item}, max chunk {n.chunk}"
            for n in request.needs
        )
        prompt = (
            "You are the Moon Director, directing a supply effort toward a space elevator in Minecraft. "
            f"Current phase: {request.phase}. Ready players: {request.readyPlayers}.\n"
            f"Recent outcomes: {', '.join(request.recent) or 'none'}.\nOutstanding needs:\n{needs}\n"
            'Choose one need. Reply with JSON only: {"template": "<id>", "quantity": <int>, '
            '"briefing": "<one or two in-character sentences>"}.'
        )
        response = httpx.post(
            self.url,
            timeout=self.timeout,
            follow_redirects=False,
            json={
                "model": self.name,
                "temperature": 0.4,
                "max_tokens": 160,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        response.raise_for_status()
        return json.loads(response.json()["choices"][0]["message"]["content"])
