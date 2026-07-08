"""GitHub CI webhook -> Kanban repair-card automation."""

from __future__ import annotations

from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import PlatformConfig
from gateway.platforms.webhook import WebhookAdapter, _INSECURE_NO_AUTH
from hermes_cli import kanban_db as kb


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


def _make_adapter(routes) -> WebhookAdapter:
    config = PlatformConfig(
        enabled=True,
        extra={"host": "127.0.0.1", "port": 0, "routes": routes},
    )
    return WebhookAdapter(config)


def _create_app(adapter: WebhookAdapter) -> web.Application:
    app = web.Application()
    app.router.add_post("/webhooks/{route_name}", adapter._handle_webhook)
    return app


def _route_config(**overrides):
    route = {
        "secret": _INSECURE_NO_AUTH,
        "events": ["workflow_run", "check_run", "check_suite"],
        "action": "github_ci_repair_card",
        "repo": "momomojo/hermes-agent",
        "assignee": "codex-coding",
        "priority": 88,
    }
    route.update(overrides)
    return {"github-ci": route}


def _workflow_payload(*, conclusion="failure", head_sha="abc123def456") -> dict:
    return {
        "action": "completed",
        "repository": {
            "full_name": "momomojo/hermes-agent",
            "html_url": "https://github.com/momomojo/hermes-agent",
        },
        "workflow_run": {
            "name": "Python tests / shard 1",
            "status": "completed",
            "conclusion": conclusion,
            "html_url": "https://github.com/momomojo/hermes-agent/actions/runs/28911964909",
            "head_branch": "fix/runtime-gate-pr-6",
            "head_sha": head_sha,
            "pull_requests": [
                {
                    "number": 7,
                    "title": "fix(fleet): cover runtime gate worker protocol",
                    "html_url": "https://github.com/momomojo/hermes-agent/pull/7",
                }
            ],
        },
    }


def _check_run_payload() -> dict:
    return {
        "action": "completed",
        "repository": {
            "full_name": "momomojo/hermes-agent",
            "html_url": "https://github.com/momomojo/hermes-agent",
        },
        "check_run": {
            "name": "Python tests / shard 2",
            "status": "completed",
            "conclusion": "failure",
            "html_url": "https://github.com/momomojo/hermes-agent/actions/runs/28911964909/job/1",
            "head_branch": "fix/runtime-gate-pr-6",
            "head_sha": "abc123def456",
            "pull_requests": [
                {
                    "number": 7,
                    "title": "fix(fleet): cover runtime gate worker protocol",
                    "html_url": "https://github.com/momomojo/hermes-agent/pull/7",
                }
            ],
            "output": {
                "title": "pytest failed",
                "summary": "1 failed",
                "text": "NameError: name 'test_home_root' is not defined",
            },
        },
    }


@pytest.mark.asyncio
async def test_github_ci_failure_webhook_creates_linked_repair_card_idempotently(
    kanban_home,
):
    with kb.connect_closing() as conn:
        parent = kb.create_task(
            conn,
            title="Runtime gate fixes: PR #6",
            body=(
                "Opened PR #7: https://github.com/momomojo/hermes-agent/pull/7\n"
                "Branch: fix/runtime-gate-pr-6"
            ),
            assignee="codex-coding",
            workspace_kind="dir",
            workspace_path="/repo/hermes-agent",
        )
        kb.add_comment(
            conn,
            parent,
            author="worker",
            body=(
                "PR #7: https://github.com/momomojo/hermes-agent/pull/7\n"
                "Head: `abc123def456`; CI is pending.\n"
                "Handoff: https://github.com/momomojo/hermes-agent/pull/7#issuecomment-4910828186"
            ),
        )

    adapter = _make_adapter(_route_config())
    app = _create_app(adapter)

    async with TestClient(TestServer(app)) as cli:
        resp = await cli.post(
            "/webhooks/github-ci",
            json=_workflow_payload(),
            headers={
                "X-GitHub-Event": "workflow_run",
                "X-GitHub-Delivery": "delivery-001",
            },
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "kanban_card_created"
        repair = data["task_id"]
        assert data["parent_id"] == parent

        replay = await cli.post(
            "/webhooks/github-ci",
            json=_workflow_payload(),
            headers={
                "X-GitHub-Event": "workflow_run",
                "X-GitHub-Delivery": "delivery-002",
            },
        )
        assert replay.status == 200
        replay_data = await replay.json()
        assert replay_data["status"] == "kanban_card_updated"
        assert replay_data["task_id"] == repair
        assert replay_data["comment_added"] is True

        second_replay = await cli.post(
            "/webhooks/github-ci",
            json=_workflow_payload(),
            headers={
                "X-GitHub-Event": "workflow_run",
                "X-GitHub-Delivery": "delivery-003",
            },
        )
        assert second_replay.status == 200
        second_replay_data = await second_replay.json()
        assert second_replay_data["status"] == "kanban_card_updated"
        assert second_replay_data["task_id"] == repair
        assert second_replay_data["comment_added"] is False

    with kb.connect_closing() as conn:
        tasks = kb.list_tasks(conn)
        repairs = [t for t in tasks if t.id != parent]
        assert len(repairs) == 1
        task = repairs[0]
        assert task.id == repair
        assert task.assignee == "codex-coding"
        assert task.priority == 88
        assert task.workspace_kind == "dir"
        assert task.workspace_path == "/repo/hermes-agent"
        assert task.idempotency_key == "github-ci-repair:momomojo/hermes-agent:7:abc123def456"
        assert kb.parent_ids(conn, task.id) == [parent]
        assert "actions/runs/28911964909" in (task.body or "")
        assert "Python tests / shard 1" in (task.body or "")
        assert "CI is green" in (task.body or "")
        comments = kb.list_comments(conn, task.id)
        assert len(comments) == 1
        assert "Automated CI failure evidence update" in comments[0].body


@pytest.mark.asyncio
async def test_github_ci_failure_webhook_updates_existing_manual_repair_card(
    kanban_home,
):
    with kb.connect_closing() as conn:
        parent = kb.create_task(
            conn,
            title="Runtime gate fixes: PR #6",
            body="Source PR #7 https://github.com/momomojo/hermes-agent/pull/7",
            assignee="codex-coding",
        )
        repair = kb.create_task(
            conn,
            title="Repair CI blockers for Hermes runtime split PR #7",
            body=(
                "Parent t_parent_placeholder completed by opening PR #7: "
                "https://github.com/momomojo/hermes-agent/pull/7\n"
                "Head branch: `fix/runtime-gate-pr-6`, head `abc123def456`."
            ).replace("t_parent_placeholder", parent),
            assignee="codex-coding",
            parents=[parent],
        )

    adapter = _make_adapter(_route_config())
    app = _create_app(adapter)

    async with TestClient(TestServer(app)) as cli:
        resp = await cli.post(
            "/webhooks/github-ci",
            json=_workflow_payload(),
            headers={
                "X-GitHub-Event": "workflow_run",
                "X-GitHub-Delivery": "delivery-003",
            },
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "kanban_card_updated"
        assert data["task_id"] == repair
        assert data["parent_id"] == parent
        assert data["comment_added"] is True

    with kb.connect_closing() as conn:
        tasks = kb.list_tasks(conn)
        assert len(tasks) == 2
        task = kb.get_task(conn, repair)
        assert task is not None
        assert task.idempotency_key == "github-ci-repair:momomojo/hermes-agent:7:abc123def456"
        comments = kb.list_comments(conn, repair)
        assert len(comments) == 1
        assert "Automated CI failure evidence update" in comments[0].body
        assert "actions/runs/28911964909" in comments[0].body


@pytest.mark.asyncio
async def test_github_ci_failure_without_origin_creates_unresolved_triage_card(
    kanban_home,
):
    adapter = _make_adapter(_route_config())
    app = _create_app(adapter)

    async with TestClient(TestServer(app)) as cli:
        resp = await cli.post(
            "/webhooks/github-ci",
            json=_workflow_payload(),
            headers={
                "X-GitHub-Event": "workflow_run",
                "X-GitHub-Delivery": "delivery-004",
            },
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "kanban_card_created"
        assert data["parent_id"] is None
        assert data["triage"] is True

    with kb.connect_closing() as conn:
        tasks = kb.list_tasks(conn)
        assert len(tasks) == 1
        task = tasks[0]
        assert task.status == "triage"
        assert "unresolved-origin" in (task.body or "")
        assert kb.parent_ids(conn, task.id) == []


@pytest.mark.asyncio
async def test_check_run_failure_includes_output_tail_in_repair_card(kanban_home):
    adapter = _make_adapter(_route_config())
    app = _create_app(adapter)

    async with TestClient(TestServer(app)) as cli:
        resp = await cli.post(
            "/webhooks/github-ci",
            json=_check_run_payload(),
            headers={
                "X-GitHub-Event": "check_run",
                "X-GitHub-Delivery": "delivery-005",
            },
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "kanban_card_created"

    with kb.connect_closing() as conn:
        tasks = kb.list_tasks(conn)
        assert len(tasks) == 1
        body = tasks[0].body or ""
        assert "Python tests / shard 2" in body
        assert "NameError: name 'test_home_root' is not defined" in body


@pytest.mark.asyncio
async def test_github_ci_success_webhook_does_not_create_repair_card(kanban_home):
    adapter = _make_adapter(_route_config())
    app = _create_app(adapter)

    async with TestClient(TestServer(app)) as cli:
        resp = await cli.post(
            "/webhooks/github-ci",
            json=_workflow_payload(conclusion="success"),
            headers={
                "X-GitHub-Event": "workflow_run",
                "X-GitHub-Delivery": "delivery-006",
            },
        )
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "ignored"
        assert data["reason"] == "ci_non_failure"

    with kb.connect_closing() as conn:
        assert kb.list_tasks(conn) == []
