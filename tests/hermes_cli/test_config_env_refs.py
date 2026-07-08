import textwrap

from hermes_cli import config as config_mod
from hermes_cli.config import load_config, save_config


def _write_config(tmp_path, body: str):
    (tmp_path / "config.yaml").write_text(textwrap.dedent(body), encoding="utf-8")


def _read_config(tmp_path) -> str:
    return (tmp_path / "config.yaml").read_text(encoding="utf-8")


def test_save_config_preserves_env_refs_on_unrelated_change(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("TU_ZI_API_KEY", "sk-realsecret")
    monkeypatch.setenv("ALT_SECRET", "alt-secret")
    _write_config(
        tmp_path,
        """\
        custom_providers:
          - name: tuzi
            base_url: https://api.tu-zi.com
            api_key: ${TU_ZI_API_KEY}
            headers:
              Authorization: Bearer ${ALT_SECRET}
            model: claude-opus-4-6
        model:
          default: claude-opus-4-6
        """,
    )

    config = load_config()
    config["model"]["default"] = "doubao-pro"
    save_config(config)

    saved = _read_config(tmp_path)
    assert "api_key: ${TU_ZI_API_KEY}" in saved
    assert "Authorization: Bearer ${ALT_SECRET}" in saved
    assert "sk-realsecret" not in saved
    assert "alt-secret" not in saved


def test_save_config_preserves_unresolved_env_refs(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("MISSING_SECRET", raising=False)
    _write_config(
        tmp_path,
        """\
        custom_providers:
          - name: unresolved
            api_key: ${MISSING_SECRET}
            model: claude-opus-4-6
        model:
          default: claude-opus-4-6
        """,
    )

    config = load_config()
    config["display"]["compact"] = True
    save_config(config)

    assert "api_key: ${MISSING_SECRET}" in _read_config(tmp_path)


def test_save_config_allows_intentional_secret_value_change(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("TU_ZI_API_KEY", "sk-old-secret")
    _write_config(
        tmp_path,
        """\
        custom_providers:
          - name: tuzi
            api_key: ${TU_ZI_API_KEY}
            model: claude-opus-4-6
        model:
          default: claude-opus-4-6
        """,
    )

    config = load_config()
    config["custom_providers"][0]["api_key"] = "sk-new-secret"
    save_config(config)

    saved = _read_config(tmp_path)
    assert "api_key: sk-new-secret" in saved
    assert "${TU_ZI_API_KEY}" not in saved


def test_save_config_preserves_template_when_env_rotates_after_load(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("TU_ZI_API_KEY", "sk-old-secret")
    _write_config(
        tmp_path,
        """\
        custom_providers:
          - name: tuzi
            api_key: ${TU_ZI_API_KEY}
            model: claude-opus-4-6
        model:
          default: claude-opus-4-6
        """,
    )

    config = load_config()
    monkeypatch.setenv("TU_ZI_API_KEY", "sk-rotated-secret")
    config["model"]["default"] = "doubao-pro"
    save_config(config)

    saved = _read_config(tmp_path)
    assert "api_key: ${TU_ZI_API_KEY}" in saved
    assert "sk-old-secret" not in saved
    assert "sk-rotated-secret" not in saved


def test_save_config_keeps_edited_partial_template_strings_literal(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("ALT_SECRET", "alt-secret")
    _write_config(
        tmp_path,
        """\
        custom_providers:
          - name: tuzi
            headers:
              Authorization: Bearer ${ALT_SECRET}
            model: claude-opus-4-6
        model:
          default: claude-opus-4-6
        """,
    )

    config = load_config()
    config["custom_providers"][0]["headers"]["Authorization"] = "Token alt-secret"
    save_config(config)

    saved = _read_config(tmp_path)
    assert "Authorization: Token alt-secret" in saved
    assert "Authorization: Bearer ${ALT_SECRET}" not in saved


def test_save_config_falls_back_to_positional_matching_for_duplicate_names(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("FIRST_SECRET", "first-secret")
    monkeypatch.setenv("SECOND_SECRET", "second-secret")
    _write_config(
        tmp_path,
        """\
        custom_providers:
          - name: duplicate
            api_key: ${FIRST_SECRET}
            model: claude-opus-4-6
          - name: duplicate
            api_key: ${SECOND_SECRET}
            model: doubao-pro
        model:
          default: claude-opus-4-6
        """,
    )

    config = load_config()
    config["display"]["compact"] = True
    save_config(config)

    saved = _read_config(tmp_path)
    assert saved.count("name: duplicate") == 2
    assert "api_key: ${FIRST_SECRET}" in saved
    assert "api_key: ${SECOND_SECRET}" in saved
    assert "first-secret" not in saved
    assert "second-secret" not in saved


def test_save_config_write_path_preserves_templates_and_updates_cache(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("RUNTIME_SECRET", "sk-runtime")
    config_mod._LAST_EXPANDED_CONFIG_BY_PATH.clear()
    _write_config(
        tmp_path,
        """\
        custom_providers:
          - name: runtime
            api_key: ${RUNTIME_SECRET}
            model: claude-opus-4-6
        model:
          default: claude-opus-4-6
        """,
    )
    config = load_config()
    config["display"]["compact"] = True

    events = []
    writes = []
    expected_state = object()
    config_path = tmp_path / "config.yaml"
    cache_key = str(config_path)

    def fake_atomic_yaml_write(path, data, extra_content=None, **kwargs):
        events.append("atomic")
        writes.append(
            {
                "path": path,
                "data": data,
                "extra_content": extra_content,
                "kwargs": kwargs,
            }
        )

    def fake_secure_file(path):
        assert events == ["atomic"]
        assert config_mod._LAST_EXPANDED_CONFIG_BY_PATH[cache_key]["display"].get(
            "compact"
        ) is not True
        events.append("secure")

    monkeypatch.setattr("utils.atomic_yaml_write", fake_atomic_yaml_write)
    monkeypatch.setattr(config_mod, "_secure_file", fake_secure_file)

    save_config(config, expected_state=expected_state)

    assert events == ["atomic", "secure"]
    assert len(writes) == 1
    assert writes[0]["path"] == config_path
    assert writes[0]["kwargs"]["expected_state"] is expected_state
    assert writes[0]["data"]["custom_providers"][0]["api_key"] == "${RUNTIME_SECRET}"
    assert config_mod._LAST_EXPANDED_CONFIG_BY_PATH[cache_key]["display"][
        "compact"
    ] is True
    assert (
        config_mod._LAST_EXPANDED_CONFIG_BY_PATH[cache_key]["custom_providers"][0][
            "api_key"
        ]
        == "sk-runtime"
    )


def test_save_config_write_path_without_existing_raw_still_secures_and_caches(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config_mod._LAST_EXPANDED_CONFIG_BY_PATH.clear()
    events = []
    writes = []
    config_path = tmp_path / "config.yaml"

    def fake_atomic_yaml_write(path, data, extra_content=None, **kwargs):
        events.append("atomic")
        writes.append(
            {
                "path": path,
                "data": data,
                "extra_content": extra_content,
                "kwargs": kwargs,
            }
        )

    def fake_secure_file(path):
        if path != config_path:
            return
        assert events == ["atomic"]
        events.append("secure")

    monkeypatch.setattr("utils.atomic_yaml_write", fake_atomic_yaml_write)
    monkeypatch.setattr(config_mod, "_secure_file", fake_secure_file)

    save_config({"model": {"default": "doubao-pro"}}, strip_defaults=False)

    assert events == ["atomic", "secure"]
    assert len(writes) == 1
    assert writes[0]["path"] == config_path
    assert "expected_state" not in writes[0]["kwargs"]
    assert writes[0]["data"]["model"]["default"] == "doubao-pro"
    assert config_mod._LAST_EXPANDED_CONFIG_BY_PATH[str(config_path)]["model"][
        "default"
    ] == "doubao-pro"
