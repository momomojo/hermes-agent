"""Compatibility entrypoint for the Mac-mini fork's preserved e2e workflow.

Upstream retired PyPI wheel/sdist distribution and replaced the old locale
artifact smoke test with a fail-closed build guard.  The fork intentionally
preserves its own ``tests.yml`` across upstream reconciliations, so that
workflow can still invoke this historical path.  Keep the entrypoint aligned
with the current supported behavior: ordinary wheel/sdist builds must be
rejected rather than silently publishing an unsupported artifact.
"""

from __future__ import annotations

import pytest

from tests.test_packaging_build_guard import _build_artifact


@pytest.mark.integration
@pytest.mark.parametrize("kind", ["sdist", "wheel"])
def test_retired_artifact_distribution_is_rejected(kind, tmp_path):
    result = _build_artifact(kind, tmp_path, nix_build=False)

    assert result.returncode != 0
    assert "Building wheels or sdists for hermes-agent is not supported" in result.stderr
