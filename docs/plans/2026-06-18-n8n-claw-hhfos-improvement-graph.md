# n8n-claw-inspired HHFOS improvement graph

Parent card: `t_4494b076` — Hermes-native implementation, no migration to n8n.

## Slice graph

1. Action Board unifier + delegated queue semantics
   - Status: first production slice implemented locally in `/Users/agent/.hermes/scripts`.
   - Files:
     - `/Users/agent/.hermes/scripts/action_registry_delegate.py`
     - `/Users/agent/.hermes/scripts/jarvis_briefing_queue.py`
     - `/Users/agent/.hermes/scripts/mohib_action_board.py` (existing renderer verified)
     - `/Users/agent/.hermes/scripts/tests/test_action_board_delegation.py`
   - Contract:
     - delegation records `delegated_task_id`;
     - registry item moves to `status: in-flight`;
     - repeated delegation reuses existing `delegated_task_id` instead of creating a duplicate;
     - Jarvis BRIEFING suppresses active delegated cards;
     - Notes Action Board renders delegated work under `IN PROCESS / DELEGATED`.

2. Hybrid memory retrieval
   - Child card: `t_67f65233` (`nas-ops`).
   - Contract: RRF across vector/full-text/exact/entity branches, metadata/time decay, privacy-safe tests.

3. Secret-safe credential intake links
   - Child card: `t_2031e639` (`codex-coding`).
   - Contract: TTL/single-use token model, no secrets in logs, local-only form/API or CLI scaffold.

4. File/artifact lifecycle registry
   - Child card: `t_51971557` (`codex-coding`).
   - Contract: TTL, source, MIME, sensitivity, task/session linkage, promote/cleanup tests.

5. Open-loop consolidator + watchdog result ledger
   - Child card: `t_e910202a` (`codex-coding`).
   - Contract: unify stale blocked loops, health-guard outcomes, and worker close-out rows into a replayable ledger.

6. Browser session registry
   - Child card: `t_fe5ec8a5` (`codex-coding`).
   - Contract: track durable browser/CDP/real-Chrome session handles without secrets or cookie export.

7. Capability catalog + profile/persona registry
   - Child card: `t_8e366544` (`codex-coding`).
   - Contract: machine-readable lanes, permissions, tools, skills, and persona surfaces for routing.

8. Project memory
   - Child card: `t_79fc743e` (`codex-coding`).
   - Contract: project-scoped durable context files/templates that stay outside prompt-cache-breaking runtime mutation.

## Review gate

This parent should stay `review-required` until the new script/test slice is reviewed. No external sends, credential changes, destructive deletes, production restarts, or OpenRouter fallback were performed.
