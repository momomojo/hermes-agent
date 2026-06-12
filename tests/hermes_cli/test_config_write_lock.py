"""Concurrency tests for the config read-modify-write lock + stale-write guard.

Regression coverage for the 2026-06-12 near-miss: a fleet-wide codex-cutover
sweep and a per-profile model.max_tokens override wrote the same profile
config.yaml within seconds.  atomic_yaml_write made each write crash-safe,
but nothing serialized the read→modify→write cycles, so concurrent updates
raced last-writer-wins and only luck prevented a lost update.

The guard has two layers (mirroring the kanban claim-lock pattern):
- utils.config_file_lock — advisory flock on a sidecar ``.config.lock``,
  held across the FULL read→edit→os.replace cycle;
- a stale-write guard (``expected_state`` mtime+hash snapshot) that aborts
  the os.replace when a writer that bypassed the lock landed mid-cycle.
"""

import multiprocessing
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml

import utils
from utils import (
    ConfigWriteConflictError,
    atomic_roundtrip_yaml_update,
    atomic_yaml_write,
    config_file_lock,
    config_lock_path,
    file_write_state,
    locked_yaml_mutate,
)

ITERATIONS = 20

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="fork + flock are POSIX-only"
)


def _seed_config(path: Path) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "model": {"default": "some-model", "max_tokens": 0},
                "auxiliary": {"counter": 0, "models": []},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def _read_yaml(path) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


# ---------------------------------------------------------------------------
# Worker processes for the two-concurrent-writers test.  Top-level so they
# work under any multiprocessing start method.
# ---------------------------------------------------------------------------

def _max_tokens_writer(config_path, barrier, violations):
    """The `hermes config set model.max_tokens N` path (roundtrip update)."""
    barrier.wait(timeout=30)
    last_aux = -1
    for i in range(1, ITERATIONS + 1):
        atomic_roundtrip_yaml_update(config_path, "model.max_tokens", i)
        cfg = _read_yaml(config_path)
        # Our own just-written value must survive any interleaved writer.
        tokens = (cfg.get("model") or {}).get("max_tokens")
        if tokens is None or tokens < i:
            violations.put(
                f"max_tokens writer iter {i}: own write lost (saw {tokens})"
            )
        # The other writer's block must never vanish or move backwards.
        aux = (cfg.get("auxiliary") or {}).get("counter")
        if aux is None:
            violations.put(f"max_tokens writer iter {i}: auxiliary block vanished")
        elif aux < last_aux:
            violations.put(
                f"max_tokens writer iter {i}: auxiliary counter regressed "
                f"{last_aux} -> {aux}"
            )
        else:
            last_aux = aux
        if (cfg.get("model") or {}).get("default") != "some-model":
            violations.put(f"max_tokens writer iter {i}: model.default clobbered")


def _auxiliary_writer(config_path, barrier, violations):
    """A programmatic saver rewriting the auxiliary: block (sweep path)."""
    barrier.wait(timeout=30)
    last_tokens = -1
    for i in range(1, ITERATIONS + 1):
        def _mut(cfg, i=i):
            aux = cfg.setdefault("auxiliary", {})
            aux["counter"] = i
            aux["models"] = [f"aux-model-{i}"]

        locked_yaml_mutate(config_path, _mut)
        cfg = _read_yaml(config_path)
        aux = cfg.get("auxiliary") or {}
        if aux.get("counter") is None or aux["counter"] < i:
            violations.put(
                f"auxiliary writer iter {i}: own write lost (saw {aux.get('counter')})"
            )
        tokens = (cfg.get("model") or {}).get("max_tokens")
        if tokens is None:
            violations.put(f"auxiliary writer iter {i}: model.max_tokens vanished")
        elif tokens < last_tokens:
            violations.put(
                f"auxiliary writer iter {i}: max_tokens regressed "
                f"{last_tokens} -> {tokens}"
            )
        else:
            last_tokens = tokens


def _blocked_child(config_path):
    locked_yaml_mutate(config_path, lambda cfg: cfg.update(child="wrote"))


@posix_only
class TestConcurrentWriters:
    def test_two_concurrent_writers_neither_change_lost(self, tmp_path):
        """The incident shape: one writer edits model.max_tokens, another

        rewrites the auxiliary: block, concurrently, against the same
        config.yaml.  With the full-cycle lock neither change may be lost,
        regress, or clobber untouched keys.
        """
        ctx = multiprocessing.get_context("fork")
        config_path = tmp_path / "config.yaml"
        _seed_config(config_path)

        barrier = ctx.Barrier(2)
        violations = ctx.Queue()
        procs = [
            ctx.Process(
                target=_max_tokens_writer,
                args=(str(config_path), barrier, violations),
            ),
            ctx.Process(
                target=_auxiliary_writer,
                args=(str(config_path), barrier, violations),
            ),
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=120)
            assert p.exitcode == 0

        found = []
        while not violations.empty():
            found.append(violations.get_nowait())
        assert not found, "lost updates detected:\n" + "\n".join(found)

        final = _read_yaml(config_path)
        assert final["model"]["max_tokens"] == ITERATIONS
        assert final["model"]["default"] == "some-model"
        assert final["auxiliary"]["counter"] == ITERATIONS
        assert final["auxiliary"]["models"] == [f"aux-model-{ITERATIONS}"]

    def test_lock_blocks_other_process_until_released(self, tmp_path):
        """Deterministic serialization: while this process holds the lock, a

        child's full read-modify-write cycle must block; once released, the
        child's edit lands and composes with ours.
        """
        ctx = multiprocessing.get_context("fork")
        config_path = tmp_path / "config.yaml"
        _seed_config(config_path)

        with config_file_lock(config_path):
            p = ctx.Process(target=_blocked_child, args=(str(config_path),))
            p.start()
            time.sleep(0.5)  # let the child reach (and block on) the flock
            assert "child" not in _read_yaml(config_path), (
                "child wrote inside our critical section — lock not held"
            )
            # Our own locked cycle still works (re-entrant acquisition).
            locked_yaml_mutate(config_path, lambda cfg: cfg.update(parent="wrote"))

        p.join(timeout=30)
        assert p.exitcode == 0
        final = _read_yaml(config_path)
        assert final["parent"] == "wrote"
        assert final["child"] == "wrote"  # neither writer lost


class TestStaleWriteGuard:
    def test_conflict_raised_when_unlocked_writer_lands(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        _seed_config(config_path)
        snapshot = file_write_state(config_path)

        # A writer that bypasses the lock lands between our read and write.
        atomic_yaml_write(config_path, {"model": {"max_tokens": 999}})
        foreign_text = config_path.read_text(encoding="utf-8")

        with pytest.raises(ConfigWriteConflictError):
            atomic_yaml_write(
                config_path, {"mine": True}, expected_state=snapshot
            )

        # The foreign write must not be clobbered, and no temp files leak.
        assert config_path.read_text(encoding="utf-8") == foreign_text
        assert not [f for f in tmp_path.iterdir() if ".tmp" in f.name]

    def test_absent_file_snapshot_conflicts_after_creation(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        snapshot = file_write_state(config_path)  # None — file absent at read
        atomic_yaml_write(config_path, {"created": "elsewhere"})
        with pytest.raises(ConfigWriteConflictError):
            atomic_yaml_write(config_path, {"mine": True}, expected_state=snapshot)

    def test_roundtrip_update_retry_preserves_foreign_change(
        self, tmp_path, monkeypatch
    ):
        """A non-locking writer lands mid-cycle once: the cycle must abort,

        re-read, and re-apply — keeping BOTH the foreign change and ours.
        """
        config_path = tmp_path / "config.yaml"
        _seed_config(config_path)
        real_guard = utils._replace_with_guard
        state = {"fired": False}

        def racing_guard(tmp, path, expected):
            if not state["fired"]:
                state["fired"] = True
                data = _read_yaml(path)
                data["foreign_key"] = "must-survive"
                atomic_yaml_write(path, data)
            return real_guard(tmp, path, expected)

        monkeypatch.setattr(utils, "_replace_with_guard", racing_guard)
        atomic_roundtrip_yaml_update(config_path, "model.max_tokens", 4096)

        final = _read_yaml(config_path)
        assert final["foreign_key"] == "must-survive"
        assert final["model"]["max_tokens"] == 4096

    def test_roundtrip_update_raises_after_exhausted_retries(
        self, tmp_path, monkeypatch
    ):
        config_path = tmp_path / "config.yaml"
        _seed_config(config_path)
        real_guard = utils._replace_with_guard
        state = {"injecting": False}

        def always_racing(tmp, path, expected):
            if not state["injecting"]:
                state["injecting"] = True
                try:
                    data = _read_yaml(path)
                    data["foreign"] = data.get("foreign", 0) + 1
                    atomic_yaml_write(path, data)
                finally:
                    state["injecting"] = False
            return real_guard(tmp, path, expected)

        monkeypatch.setattr(utils, "_replace_with_guard", always_racing)
        with pytest.raises(ConfigWriteConflictError):
            atomic_roundtrip_yaml_update(config_path, "model.max_tokens", 1)


class TestLockMechanics:
    def test_lock_path_is_sidecar_dotfile(self, tmp_path):
        assert (
            config_lock_path(tmp_path / "profiles" / "radulator" / "config.yaml")
            == tmp_path / "profiles" / "radulator" / ".config.lock"
        )

    def test_reentrant_acquisition_does_not_deadlock(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        done = threading.Event()

        def work():
            with config_file_lock(config_path):
                with config_file_lock(config_path):
                    # Locked helpers re-acquire internally too.
                    atomic_roundtrip_yaml_update(config_path, "a.b", 1)
            done.set()

        t = threading.Thread(target=work, daemon=True)
        t.start()
        t.join(timeout=30)
        assert done.is_set(), "re-entrant config_file_lock deadlocked"
        assert _read_yaml(config_path)["a"]["b"] == 1

    def test_locked_yaml_mutate_skip_write(self, tmp_path):
        config_path = tmp_path / "config.yaml"
        _seed_config(config_path)
        before = config_path.read_text(encoding="utf-8")
        result = locked_yaml_mutate(config_path, lambda cfg: utils.SKIP_WRITE)
        assert result is None
        assert config_path.read_text(encoding="utf-8") == before


class TestConfigUpdateContextManager:
    def test_full_cycle_persists_under_lock(self, monkeypatch, tmp_path):
        home = tmp_path / "hermes_home"
        home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(home))
        (home / "config.yaml").write_text(
            yaml.safe_dump({"model": {"default": "some-model"}}), encoding="utf-8"
        )
        from hermes_cli.config import config_update

        with config_update() as cfg:
            cfg.setdefault("model", {})["max_tokens"] = 8192

        saved = _read_yaml(home / "config.yaml")
        assert saved["model"]["max_tokens"] == 8192
        assert saved["model"]["default"] == "some-model"

    def test_conflict_when_unlocked_writer_races_the_cycle(
        self, monkeypatch, tmp_path
    ):
        home = tmp_path / "hermes_home"
        home.mkdir()
        monkeypatch.setenv("HERMES_HOME", str(home))
        config_path = home / "config.yaml"
        config_path.write_text(
            yaml.safe_dump({"model": {"default": "some-model"}}), encoding="utf-8"
        )
        from hermes_cli.config import config_update

        with pytest.raises(ConfigWriteConflictError):
            with config_update() as cfg:
                cfg.setdefault("model", {})["max_tokens"] = 1
                # Unlocked writer lands mid-cycle (e.g. manual edit).
                config_path.write_text(
                    "model:\n  default: foreign-edit\n", encoding="utf-8"
                )

        # The racing write survives; our stale save was aborted.
        assert "foreign-edit" in config_path.read_text(encoding="utf-8")
