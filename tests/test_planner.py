from server.planner import PlanRequest, checked, heuristic, plan
from test_community import environment
from test_minecraft import headers

NEEDS = [
    {
        "template": "iron_delivery",
        "item": "minecraft:iron_ingot",
        "remaining": 200,
        "chunk": 16,
    },
    {
        "template": "copper_delivery",
        "item": "minecraft:copper_ingot",
        "remaining": 120,
        "chunk": 16,
    },
]
BODY = {
    "phase": "foundations",
    "needs": NEEDS,
    "recent": ["iron:done"],
    "readyPlayers": 2,
}


def test_heuristic_targets_largest_shortfall_within_chunk():
    proposal = heuristic(PlanRequest(**BODY))
    assert (proposal.template, proposal.quantity, proposal.briefing) == (
        "iron_delivery",
        16,
        None,
    )


def test_valid_model_output_is_used_and_cleaned():
    result = plan(
        PlanRequest(**BODY),
        lambda _: {
            "template": "copper_delivery",
            "quantity": 8,
            "briefing": "  Bring copper.\x07 ",
        },
    )
    assert result.source == "model"
    assert result.proposal.model_dump() == {
        "template": "copper_delivery",
        "quantity": 8,
        "briefing": "Bring copper.",
    }


def test_unsafe_model_output_falls_back_to_heuristic():
    request = PlanRequest(**BODY)
    for bad in (
        None,
        "text",
        {"template": "gold_delivery", "quantity": 1},
        {"template": "iron_delivery", "quantity": 17},
        {"template": "iron_delivery", "quantity": 0},
        {"template": "iron_delivery", "quantity": True},
        {"template": "iron_delivery", "quantity": 1, "briefing": "x" * 481},
    ):
        assert checked(request, bad) is None
        assert plan(request, lambda _, value=bad: value).source == "heuristic"

    def broken(_):
        raise RuntimeError("model offline")

    assert plan(request, broken).source == "heuristic"


def test_route_requires_server_token_and_rejects_malformed_bodies(environment):
    env = environment
    assert env.client.post("/api/auth/minecraft/plan", json=BODY).status_code == 401
    assert (
        env.client.post(
            "/api/auth/minecraft/plan", headers=headers(env), json={**BODY, "needs": []}
        ).status_code
        == 422
    )
    assert (
        env.client.post(
            "/api/auth/minecraft/plan", headers=headers(env), json={**BODY, "extra": 1}
        ).status_code
        == 422
    )
    response = env.client.post(
        "/api/auth/minecraft/plan", headers=headers(env), json=BODY
    )
    assert response.status_code == 200
    assert response.json()["source"] == "heuristic"
    env.app.state.planner_model = lambda _: {
        "template": "copper_delivery",
        "quantity": 4,
        "briefing": "Copper.",
    }
    assert env.client.post(
        "/api/auth/minecraft/plan", headers=headers(env), json=BODY
    ).json() == {
        "proposal": {
            "template": "copper_delivery",
            "quantity": 4,
            "briefing": "Copper.",
        },
        "source": "model",
    }
