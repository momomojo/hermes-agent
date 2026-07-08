# Hermes Project Memory

Project Memory is a lightweight, file-backed project narrative layer inspired by n8n-claw project markdown docs. It is intentionally local and explicit: one `memory.md` file plus one `metadata.json` sidecar per project under:

```text
$HERMES_HOME/project-memory/<project-id>/
```

## What belongs here

Use Project Memory for durable, human-readable project context that should outlive one session but should not be injected into every prompt by default:

- current project goals and decisions;
- links to canonical Kanban cards;
- relevant skills/runbooks;
- recurring cron jobs or watchdogs;
- artifact registry ids/paths for deliverables;
- Hindsight/entity references when deeper retrieval is needed.

Do not store secrets, raw credentials, OAuth material, cookies, private keys, or large pasted transcripts here.

## CLI examples

```bash
# Create or replace a project note
hermes project-memory update hhfos-ops \
  --title "HHFOS Ops" \
  --content "# HHFOS Ops\n\nCanonical operating notes.\n" \
  --kanban-task t_4494b076 \
  --skill hhfos-kanban-workflow \
  --cron-job 10f3002b3f31

# Append a note
hermes project-memory update hhfos-ops --append "2026-06-18: Added watchdog ledger."

# Show markdown or JSON
hermes project-memory show hhfos-ops
hermes project-memory show hhfos-ops --json

# List known project memories
hermes project-memory list --json
```

## Linkage model

`metadata.json` keeps structured links separate from prose:

- `kanban_tasks`: source-of-truth task cards and implementation handoffs.
- `skills`: reusable procedures that define how the project should be operated.
- `cron_jobs`: scheduled jobs/watchdogs that maintain or monitor the project.
- `artifacts`: deliverable files or artifact-registry records.
- `hindsight_entities`: retrieval/entity anchors for broader semantic memory.

This keeps Project Memory inspectable without increasing the model-facing tool schema or prompt-cache footprint.
