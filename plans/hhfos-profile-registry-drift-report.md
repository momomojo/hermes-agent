# HHFOS profile/persona registry drift report

Generated: 2026-06-19T02:29:22+00:00
Hermes root: `/Users/agent/.hermes`
Workflow source: `/Users/agent/.hermes/skills/devops/hhfos-kanban-workflow/SKILL.md`

## Drift summary

- Overall OK: `True`
- Unknown profiles: none
- Missing lanes: none
- Dispatcher mismatches: 0
- Missing kanban-worker skill: none

## Profiles

| profile | lane? | persona labels | dispatch actual/expected | SOUL | skills |
|---|---:|---|---|---|---|
| codex-coding | yes | unspecified, owner-admin, nas-ops, home-automation, code-implementation | False/False | present, 88B, sha256:f3a3fa28d0d8 | hhfos-kanban-orchestrator=yes, hhfos-kanban-workflow=yes, kanban-orchestrator=yes, kanban-worker=yes |
| default | yes | unspecified, owner-admin, google-workspace | True/True | present, 88B, sha256:f3a3fa28d0d8 | hhfos-kanban-orchestrator=yes, hhfos-kanban-workflow=yes, kanban-orchestrator=yes, kanban-worker=yes |
| financial | yes | owner-admin, medical-professional, radiology-product, finance, nas-ops, home-automation, google-workspace | False/False | present, 19228B, sha256:40d6f275b823 | hhfos-kanban-orchestrator=no, hhfos-kanban-workflow=yes, kanban-orchestrator=yes, kanban-worker=yes |
| home-assistant | yes | unspecified, home-automation | False/False | present, 88B, sha256:f3a3fa28d0d8 | hhfos-kanban-orchestrator=no, hhfos-kanban-workflow=yes, kanban-orchestrator=yes, kanban-worker=yes |
| job-medical | yes | owner-admin, medical-professional, radiology-product, finance, nas-ops, home-automation, google-workspace | False/False | present, 3591B, sha256:ea62aa93d287 | hhfos-kanban-orchestrator=no, hhfos-kanban-workflow=yes, kanban-orchestrator=no, kanban-worker=yes |
| nas-ops | yes | unspecified, nas-ops | False/False | present, 88B, sha256:f3a3fa28d0d8 | hhfos-kanban-orchestrator=no, hhfos-kanban-workflow=yes, kanban-orchestrator=yes, kanban-worker=yes |
| radulator | yes | medical-professional, radiology-product, nas-ops, home-automation, code-implementation, google-workspace | False/False | present, 3602B, sha256:99b19564b9ed | hhfos-kanban-orchestrator=yes, hhfos-kanban-workflow=yes, kanban-orchestrator=yes, kanban-worker=yes |

## Privacy note

This report does not emit SOUL.md prose, memory text, .env values, OAuth material, cookies, or config secret fields. Persona summaries are labels inferred from local aggregate text and HHFOS workflow lane descriptions.
