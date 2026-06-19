# Open-loop consolidator model (t_997092d7)

The implementation is `scripts/open_loop_consolidator.py`. It is intentionally local-first: collectors are read-only, dry-runs are default, and `--apply` writes only the consolidator state ledger.

## Inputs

The consolidator can read any combination of:

- Action Registry JSON (`--registry`) for Mohib-facing Action Board items and delegated/in-flight suppression.
- Kanban SQLite (`--kanban-db`) for blocked/ready/running cards.
- Watchdog JSONL ledger (`--watchdog-ledger`) for no-agent cron/health failures.
- Session SQLite (`--sessions-db`) for recent assistant commitment-language candidates.
- Hindsight fixture/export JSON or JSONL (`--hindsight-json`) without calling NAS services.
- Normalized fixture JSON (`--records-json`) for tests and dry-runs.

## Normalized record fields

Each open-loop signal becomes an `OpenLoopRecord`:

- `key`: stable `ol_<sha1(source:source_id)>` idempotency key.
- `source` / `source_id`: provenance used for dedupe and closure.
- `title` / `detail`: human-readable loop summary.
- `profile`: owning profile/lane hint.
- `state`: `open` or `suppressed`.
- `gate`: `mohib`, `external`, or `internal`.
- `fingerprint`: sha256 over actionable content; same fingerprint inside the throttle window is muted.
- `metadata`: source-specific hints such as `delegated_task_id`, `kanban_status`, `watchdog_status`, or session message ids.

## Action model

The consolidator emits proposals, not external side effects:

- `action_board:add`: Mohib-facing decision, credential, external communication, payment/upload/submission, or other human-gated loop.
- `kanban:create`: internal/judge/fleet/code/watchdog loop that should become or reuse a worker card.
- `suppress`: linked work is already delegated or in-flight, so Jarvis/BRIEFING should not page Mohib again.

## Throttle and closure metadata

State is stored as JSON under `$HERMES_ROOT/state/open-loop-consolidator.json` by default. Per record:

- `first_seen_at`, `last_seen_at`: provenance timeline.
- `last_emitted_at`: last non-throttled proposal time.
- `fingerprint`: duplicate detector.
- `status`: `open`, `suppressed`, or `closed`.
- `suppression`: `{reason, at}` for delegated/in-flight loops.
- `closure`: `{closed_at, reason}` when a previously tracked source disappears or becomes terminal.

A repeated identical record is moved to the `throttled` output when `now - last_emitted_at < --throttle-seconds`. If a previously open/suppressed key is absent from the current collector result, the state record is closed with `reason: source_absent_or_terminal`.

## Verification

Targeted tests:

```bash
./venv/bin/python -m pytest tests/scripts/test_open_loop_consolidator.py -q
```

Dry-run smoke:

```bash
./venv/bin/python scripts/open_loop_consolidator.py \
  --records-json /path/to/records.json \
  --state /tmp/open-loop-state.json \
  --dry-run
```
