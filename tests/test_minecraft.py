import uuid
from concurrent.futures import ThreadPoolExecutor

from server import community as api
from test_community import ALICE, BOB, ORIGIN, device, environment, login, oauth_start, mock_provider

PLAYER = "12345678-1234-1234-1234-123456789abc"


def headers(env):
    return {"Authorization": "Bearer " + env.settings.minecraft_server_token}


def start(env, player=PLAYER):
    response = env.client.post("/api/auth/minecraft/arrival", headers=headers(env),
                               json={"minecraftUuid": player, "playerName": "Astronaut"})
    assert response.status_code == 200, response.text
    return response.json()


def approve(env, challenge, user=ALICE):
    login(env, user)
    return env.client.post("/api/auth/minecraft/approve", headers={"Origin": ORIGIN},
                           json={"requestId": challenge["requestId"]})


def confirm(env, challenge, name="alice", player=PLAYER):
    return env.client.post("/api/auth/minecraft/confirm", headers=headers(env),
                           json={"minecraftUuid": player, "deviceCode": challenge["deviceCode"],
                                 "expectedAccountName": name})


def test_two_phase_arrival_reuses_oauth_but_never_issues_desktop_credentials(environment, monkeypatch):
    env = environment
    challenge = start(env)
    assert len(challenge["context"]["callSign"]) == 4
    assert not challenge["context"]["confirmed"]
    assert "deviceCode" not in challenge["verificationUri"]
    oauth_state = oauth_start(env, challenge["requestId"])
    mock_provider(monkeypatch)
    callback = env.client.get("/api/auth/github/callback", params={"state": oauth_state, "code": "fixture-code"},
                              follow_redirects=False)
    assert callback.status_code == 303
    assert "requestId=" + challenge["requestId"] in callback.headers["location"]
    assert "authResult=success" in callback.headers["location"]
    assert approve(env, challenge).status_code == 200
    assert env.client.get("/api/auth/minecraft/context/" + PLAYER, headers=headers(env)).json()["confirmed"] is False
    poll = env.client.post("/api/auth/minecraft/poll", headers=headers(env),
                           json={"minecraftUuid": PLAYER, "deviceCode": challenge["deviceCode"]})
    assert poll.json() == {"status": "approved", "accountName": "alice"}
    assert confirm(env, challenge).json() == {
        "minecraftUuid": PLAYER, "callSign": challenge["context"]["callSign"], "confirmed": True,
        "accountName": "alice", "roles": [],
    }
    assert confirm(env, challenge).status_code == 409
    assert start(env)["status"] == "confirmed"
    assert start(env)["context"]["callSign"] == challenge["context"]["callSign"]


def test_machine_auth_and_cookie_approval_are_separate(environment):
    env = environment
    body = {"minecraftUuid": PLAYER, "playerName": "Astronaut"}
    assert env.client.post("/api/auth/minecraft/arrival", json=body).status_code == 401
    assert env.client.post("/api/auth/minecraft/arrival", json=body,
                           headers={**headers(env), "Origin": ORIGIN}).status_code == 403
    challenge = start(env)
    assert env.client.post("/api/auth/minecraft/approve", headers=headers(env),
                           json={"requestId": challenge["requestId"]}).status_code == 403
    login(env)
    assert env.client.post("/api/auth/minecraft/approve", headers={"Origin": "https://attacker.example"},
                           json={"requestId": challenge["requestId"]}).status_code == 403
    assert env.client.post("/api/auth/desktop/approve", headers={"Origin": ORIGIN},
                           json={"requestId": challenge["requestId"]}).status_code == 403
    assert env.client.post("/api/auth/desktop/poll",
                           json={"deviceCode": challenge["deviceCode"]}).status_code == 403


def test_request_kind_is_server_derived_and_context_is_allowlisted(environment):
    env = environment
    challenge = start(env)
    login(env)
    details = env.client.get("/api/auth/requests/" + challenge["requestId"]).json()
    assert details == {"kind": "minecraft", "status": "pending",
                       "callSign": challenge["context"]["callSign"], "playerName": "Astronaut"}
    launcher = device(env)
    assert env.client.get("/api/auth/requests/" + launcher["requestId"]).json()["kind"] == "desktop"
    approve(env, challenge)
    context = confirm(env, challenge).json()
    assert set(context) == {"minecraftUuid", "callSign", "confirmed", "accountName", "roles"}
    assert "avatarUrl" not in context
    assert "accessToken" not in context
    assert "profiles" not in context


def test_challenges_expire_are_bound_to_uuid_and_rotation_revokes_old_links(environment):
    env = environment
    first = start(env)
    second = start(env)
    assert first["context"]["callSign"] == second["context"]["callSign"]
    assert approve(env, first).status_code == 409
    assert env.client.post("/api/auth/minecraft/poll", headers=headers(env),
                           json={"minecraftUuid": str(uuid.uuid4()), "deviceCode": second["deviceCode"]}).json() == {"status": "expired"}
    env.clock[0] += 601
    assert approve(env, second).status_code == 409
    assert confirm(env, second).status_code == 409


def test_approved_account_must_match_review_and_cannot_link_two_players(environment):
    env = environment
    first = start(env)
    second_uuid = str(uuid.uuid4())
    second = start(env, second_uuid)
    assert approve(env, first).status_code == 200
    assert confirm(env, first, "bob").status_code == 409
    assert confirm(env, first).status_code == 200
    assert approve(env, second).status_code == 409
    assert approve(env, second, BOB).status_code == 200
    assert confirm(env, second, "bob", second_uuid).status_code == 200


def test_concurrent_allocations_are_unique_and_stable(environment):
    workflow = api.MinecraftWorkflow(environment.store, environment.settings.website_url)
    players = [str(uuid.uuid4()) for _ in range(30)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda player: workflow.start(player, "Astronaut", environment.clock[0]), players))
    signs = [result["context"]["callSign"] for result in results]
    assert len(set(signs)) == len(players)
    assert workflow.start(players[0], "Renamed", environment.clock[0])["context"]["callSign"] == signs[0]


def test_exhaustion_never_reuses_a_permanent_callsign(environment):
    with environment.store.connect() as db:
        db.executemany("INSERT INTO minecraft_players VALUES (?, ?, 'Astronaut', NULL, 0, NULL)",
                       [(str(uuid.uuid4()), f"{index:04d}") for index in range(10000)])
    response = environment.client.post("/api/auth/minecraft/arrival", headers=headers(environment),
                                       json={"minecraftUuid": PLAYER, "playerName": "Astronaut"})
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "callsign_capacity"


def test_minecraft_challenges_cannot_be_approved_by_desktop_flow(environment):
    challenge = start(environment)
    login(environment)
    response = environment.client.post("/api/auth/desktop/approve", headers={"Origin": ORIGIN},
                                       json={"requestId": challenge["requestId"]})
    assert response.status_code == 403
    assert confirm(environment, challenge).status_code == 409
