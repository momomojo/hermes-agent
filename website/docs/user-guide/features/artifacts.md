---
sidebar_position: 13
title: "Artifact Lifecycle Registry"
description: "Track inbound files, generated artifacts, TTLs, and Kanban attachment linkage"
---

# Artifact Lifecycle Registry

Hermes records file-like inputs and artifacts in a local SQLite registry at
`~/.hermes/artifacts/registry.db`. The registry is metadata first: it tracks
where a file came from, its MIME type, sensitivity label, TTL, session id,
Kanban task id, board, and arbitrary JSON metadata.

It does not change existing retention for Telegram, Discord, Slack, or Kanban
attachment files. Cleanup only deletes files that were explicitly copied into
the Hermes artifact store under `~/.hermes/artifacts/blobs/`. External cache
paths and Kanban attachment paths are marked expired when their TTL passes, but
the source file is retained.

## What Gets Recorded

- Gateway inbound media such as Telegram photos, documents, audio, and other
  cached attachment paths are registered with source `gateway_inbound` and the
  active session id.
- Kanban dashboard task uploads are registered with source
  `kanban_attachment`, the task id, board, MIME type, uploader, and attachment
  id.
- Operator or script artifacts can be registered manually with
  `hermes artifacts register`.

The registry is intentionally not a model tool. Agents can still read files
through normal file and terminal paths; the registry gives operators and
automation a durable audit and cleanup layer without growing the core tool
schema.

## CLI

```bash
# List recent records.
hermes artifacts list

# Filter by session, Kanban task, source, or cleanup state.
hermes artifacts list --source gateway_inbound
hermes artifacts list --task t_51971557
hermes artifacts list --session 20260618_abc --json

# Register a file without taking cleanup ownership.
hermes artifacts register ./report.pdf \
  --source manual \
  --mime application/pdf \
  --sensitivity internal \
  --ttl 7d

# Copy a file into the Hermes artifact store. Only this copied blob is eligible
# for deletion by `cleanup`; the original file is left alone.
hermes artifacts register ./report.pdf --source manual --copy --ttl 1d

# Extend a TTL, or keep the record permanently.
hermes artifacts promote a_1234abcd --ttl 30d
hermes artifacts promote a_1234abcd --permanent

# Expire old records and delete only registry-owned blobs.
hermes artifacts cleanup --dry-run
hermes artifacts cleanup
```

TTL values accept seconds, `15m`, `2h`, `7d`, `4w`, or `permanent`.

## Telegram To Kanban

When a user sends a document or image through Telegram, the gateway adapter
downloads it into Hermes' normal local media cache and passes the local path to
the agent. The artifact registry records that path with:

- `source=gateway_inbound`
- `session_id` for the active Telegram conversation
- platform/chat/thread/message metadata
- the adapter-supplied MIME type
- `sensitivity=user-provided`

If the agent or operator attaches that file to a Kanban card through the
dashboard, the upload is copied into the board's task attachment directory and
the registry records a second row:

- `source=kanban_attachment`
- `task_id` and `board`
- Kanban attachment id and uploader metadata
- MIME type and size

This gives a durable chain from "Telegram message attachment in session X" to
"Kanban task attachment on card Y" without requiring Hermes to send files
externally or delete platform cache files.

## Cleanup Safety

`hermes artifacts cleanup` follows one hard rule: it only unlinks files that
the registry owns under `~/.hermes/artifacts/blobs/`. Files registered from
gateway caches, Kanban attachment directories, user workspaces, or arbitrary
paths are not deleted by the registry cleanup path.

Use `--copy` when you want Hermes to own a cleanup-safe duplicate. Use plain
`register` when you only want metadata, TTL expiry, search, and audit.
