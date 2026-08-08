from tools.skill_reference_guard import (
    collect_protected_references,
    summarize_protected_references,
)


def test_collector_failure_keeps_safety_index_incomplete(monkeypatch):
    """Unreadable stores must not be mistaken for an empty reference set."""
    monkeypatch.setattr(
        "tools.skill_reference_guard._collect_cron_references",
        lambda: ([], "cron scan failed: OSError"),
    )
    monkeypatch.setattr(
        "tools.skill_reference_guard._collect_kanban_references",
        lambda: ([], None),
    )
    monkeypatch.setattr(
        "tools.skill_reference_guard._collect_profile_default_references",
        lambda: ([], None),
    )

    result = collect_protected_references()

    assert result["complete"] is False
    assert result["collector_errors"] == {"cron": "cron scan failed: OSError"}


def test_bounded_summary_preserves_scan_completeness():
    result = summarize_protected_references(
        {"by_name": {}, "complete": False, "collector_errors": {"kanban": "locked"}}
    )

    assert result["complete"] is False
    assert result["collector_errors"] == {"kanban": "locked"}


def test_protected_reference_summary_is_bounded_and_aggregated():
    refs = [
        {
            "name": "life-admin-workflows",
            "source": "kanban.tasks.skills",
            "task_id": f"t_{index:08d}",
            "profile": "default",
            "status": "blocked",
        }
        for index in range(100)
    ]
    snapshot = {
        "protected_names": ["life-admin-workflows"],
        "references": refs,
        "by_name": {"life-admin-workflows": refs},
        "count": 1,
    }

    result = summarize_protected_references(snapshot, sample_limit=3)
    skill = result["summary_by_name"]["life-admin-workflows"]

    assert result["bounded"] is True
    assert result["count"] == 1
    assert result["reference_count"] == 100
    assert len(result["references"]) == 3
    assert len(result["by_name"]["life-admin-workflows"]) == 3
    assert result["references_truncated"] is True
    assert skill["total"] == 100
    assert skill["by_source"] == {"kanban.tasks.skills": 100}
    assert skill["by_status"] == {"blocked": 100}
    assert len(skill["samples"]) == 3
    assert skill["omitted"] == 97


def test_protected_reference_summary_has_global_name_cap():
    by_name = {
        f"skill-{index:03d}": [
            {
                "name": f"skill-{index:03d}",
                "source": "kanban.tasks.skills",
                "task_id": f"t_{index:08d}",
            }
        ]
        for index in range(100)
    }
    result = summarize_protected_references(
        {"by_name": by_name}, sample_limit=3, name_limit=25
    )

    assert result["count"] == 100
    assert result["reference_count"] == 100
    assert len(result["protected_names"]) == 25
    assert len(result["references"]) == 25
    assert len(result["by_name"]) == 25
    assert len(result["summary_by_name"]) == 25
    assert result["protected_names_truncated"] is True
    assert result["names_omitted"] == 75
