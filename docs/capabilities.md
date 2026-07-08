# Hermes capability catalog scaffold

The capability catalog is a local, machine-readable abstraction for installing and validating higher-level Hermes workflows without growing the core model tool schema. A capability manifest bundles the edge surfaces a workflow needs:

- skills
- plugins
- MCP servers
- cron jobs
- credential requirements
- approval gates
- smoke tests
- install, doctor, and remove plans

This is intentionally implemented as a CLI/library scaffold (`hermes capabilities`) rather than a new model-facing tool. It follows the Hermes footprint ladder: capability lives at the edge, while the core tool surface stays narrow.

## Manifest shape

Each capability lives in its own directory under `$HERMES_HOME/capabilities/<capability-id>/capability.yaml` (or `.json`). Schema version 1 requires:

```yaml
schema_version: 1
id: synthetic.echo
name: Synthetic Echo Capability
version: 0.1.0
description: Credential-free capability used to verify catalog plumbing.
owner:
  profile: default
  lane: test
approval_gates:
  - no external sends
  - no production restarts
components:
  skills: []
  plugins: []
  mcp_servers: []
  cron_jobs: []
  credentials: []
  smoke_tests:
    - id: echo-python
      kind: python
      command:
        - python
        - -c
        - print('HERMES_CAPABILITY_SMOKE_OK')
      expect_stdout_contains: HERMES_CAPABILITY_SMOKE_OK
      timeout_seconds: 10
install:
  steps:
    - Validate manifest schema.
    - Install/copy listed skills and plugins if absent.
doctor:
  checks:
    - Manifest validates.
remove:
  steps:
    - Disable cron jobs owned by the capability.
```

Credential entries describe requirements and destinations only; they must not embed secret values. Future installers should request secrets through `credential-intake` or a user-approved vault path.

## CLI

```bash
hermes capabilities init
hermes capabilities list
hermes capabilities validate
hermes capabilities doctor
hermes capabilities smoke synthetic.echo
hermes capabilities plan synthetic.echo install
hermes capabilities plan synthetic.echo remove
```

All commands accept `--catalog-dir` for tests or alternate catalogs and `--json` for automation.

## Current scaffold behavior

- `init` creates a credential-free synthetic capability.
- `validate`/`doctor` check the schema, unknown components, relative local file references, credential non-embedding, and smoke-test definitions.
- `smoke` runs declared local smoke commands with bounded timeouts.
- `plan` prints install/doctor/remove plans but does not mutate production config, install credentials, send external messages, or restart services.

## Future install/remove implementation notes

A production installer should stay explicit and reviewable:

1. Validate the manifest first.
2. Copy or register capability-owned skills/plugins only after confirming ownership and collision behavior.
3. Register MCP servers and cron jobs via existing config/CLI surfaces, not by adding a new model tool.
4. Request required credentials through `hermes credential-intake` or 1Password-backed approved flows; never store raw secrets in manifests.
5. Run `doctor` and smoke tests before declaring the capability installed.
6. On removal, disable capability-owned cron/MCP entries but leave shared skills/plugins and credentials unless the manifest marks them as owned and the user approves deletion.
