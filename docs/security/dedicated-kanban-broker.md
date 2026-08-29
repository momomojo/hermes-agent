# Dedicated Kanban broker

The dedicated Kanban broker is an opt-in macOS security boundary. It is not
installed or activated by an ordinary Hermes upgrade. Both public profile
flags and both private service flags default to exact `false`:

```yaml
kanban:
  dedicated_broker_enabled: false
  trusted_publisher_enabled: false
```

The boundary contract is `hermes.dedicated_broker_identity.v1`. A newly
provisioned model service account receives a broker-materialized, `.git`-free
workspace and may edit and test files there. A separate broker UID owns the authority database, receipt
key, private Git object store, commit journal, and immutable publisher bundles.
The broker has no IP-network authority and no GitHub credential. A separate
publisher UID receives only a receipt-bound Git bundle through its authenticated
publisher socket.

## Identities and immutable runtime

Provision distinct non-root broker, controller, publisher, and model accounts
(for example `_hermesbroker`, `_hermescontroller`, `_hermespublisher`, and
`_hermesmodel`),
plus a root operator surface. Controller, publisher, operator, and workspace
groups are distinct. The broker belongs to all four; the model belongs only to
the workspace group. Generate and review the exact identity plan, store it as a
root-owned mode `0600` file, then run:

```console
sudo python -m hermes_cli.kanban_broker_install provision-identities \
  --plan /private/var/db/hermes-kanban/install/identities.json
```

The model account is never an existing interactive Hermes account. Its launchd
job sets `HOME`, `HERMES_HOME`, every XDG home, and `GNUPGHOME` below a private
model-owned mode `0700` worker root under the install root. Named worker
profiles live at `profiles/<profile>` below that root and must also be real,
model-owned mode `0700` directories.

The service uses fixed `/usr/bin/git`, a pinned root-owned Python executable,
and a root-owned, non-writable snapshot of the required `hermes_cli` modules.
The broker and reverse-worker launchd jobs both bind the exact Python and
package digests. No worker-writable Python path, Git config, hook, replace ref,
graft, or alternates file is accepted.

## Disabled-first asset installation

Place every private asset below one dedicated install root, for example
`/private/var/db/hermes-kanban`. Render the service config, Seatbelt profile,
broker and worker launchd plists, surface client configs, immutable runtime
assets, filesystem plan, and base64 payload manifest using the reviewed Python
renderers. `render_broker_service_config()` always emits `enabled: false` and
`trusted_publisher_enabled: false`.

Before staging, provision each required named model profile inside the isolated
worker root. A provider credential may exist only in that profile's `.env` when
the selected model actually requires one. GitHub, Copilot, Git, SSH, netrc,
Docker, npm, GPG, gh CLI, embedded GitHub-token, symlink, and external-secret
authority is forbidden anywhere in the worker root. Do not clone an ordinary
interactive Hermes home into this location.

Store the plan and payload manifest root-owned mode `0600`, then run:

```console
sudo python -m hermes_cli.kanban_broker_install provision-assets \
  --plan /private/var/db/hermes-kanban/install/filesystem.json \
  --payloads /private/var/db/hermes-kanban/install/payloads.json \
  --config /private/var/db/hermes-kanban/service.json
sudo python -m hermes_cli.kanban_broker_install verify-disabled \
  --config /private/var/db/hermes-kanban/service.json
```

Provisioning first proves both launchd labels are unloaded and disabled. It is
idempotent only for byte-identical assets and never rotates an existing key.
Symlinks, hard links, wrong owners or modes, mutable runtime bytes, overlapping
authority directories, and changed payloads fail closed.

## Mandatory activation canaries

Activation is one root-only transaction. It stages the broker in
non-publishing mode, starts both launchd services, and invokes the installed
`kanban_broker_canary.py` runner directly. Callers cannot provide canary
booleans or an attestation file. The runner records observed `PASS`, `FAIL`,
`MISSING`, or `ERROR` results; only all-`PASS` evidence is signed. The HMAC
attestation binds the exact service-config digest, install nonce, installed
runner digest, Python digest, Git digest, package manifest, and issuance time.

The 16 mandatory probes cover root execution, distinct identities, exact group
membership, socket-parent traversal, model denial of broker state and database,
model workspace editing, publisher-bundle access, all four socket matrices,
broker network denial, both launchd environments plus the isolated worker-home
credential boundary, a real model-UID terminal
process, and an `osascript`-driven model-UID process. Missing files, unavailable
processes, permission-drop errors, connection errors, or generic automation
errors are not treated as denial.

After independent exact-head review, activate with:

```console
sudo python -m hermes_cli.kanban_broker_install activate \
  --config /private/var/db/hermes-kanban/service.json \
  --plist /Library/LaunchDaemons/ai.hermes.kanban-broker.plist \
  --worker-plist /Library/LaunchDaemons/ai.hermes.kanban-worker.plist \
  --operator-config /private/var/db/hermes-kanban/operator/client.json
```

Activation enables publishing only after the root runner succeeds and an
authenticated idle-service readback returns zero in-flight mutations. Any
failure disables both labels, boots out both jobs, and restores both config
flags to false. Only after this succeeds may the public profile set both opt-in
flags true. There is no fallback to the legacy same-UID Git path.

## Controller, worker, and publisher flow

The root operator registers a canonical GitHub repository and trusted checkout
through `kanban broker-register`. Registration rejects model-mutable Git control
state and is replayable after response loss. A no-agent controller creates
exact `ready` tasks through `kanban trusted-create`; every dispatch-affecting
field is sealed in `hermes.kanban_dispatch_authority.v1`. The dispatcher uses
`kanban broker-dispatch` and polls `kanban broker-dispatch-status`. Dispatch is
runtime-aware, replayable by operation ID, and restart recovery never trusts
task prose.

After a successful model turn, the broker snapshots the `.git`-free workspace
with descriptor-safe traversal, writes the local commit through fixed Git
plumbing, journals it, and emits `hermes.trusted_local_commit.v1` with marker
`AWAITING_TRUSTED_PUBLISHER v1`. The publisher exports the exact immutable
bundle using `kanban broker-export`. It discovers work only through the
authenticated, bounded `list_publish_obligations` RPC: the broker returns
verified, still-pending receipts in stable `created_at`/`receipt_id` order and
removes an obligation from that view only after an exact publish
acknowledgement. The publisher never reads the broker database or worker
workspace.

The receipt binds the commit parent (`base_sha`) separately from the protected
pull-request target (`target_base_sha`). A successful publication finalizes the
branch but does not move the broker's protected base before merge. If exact-head
CI fails, the controller may submit one authenticated
`hermes.publisher_correction_request.v1`: the broker revokes and removes the old
publisher obligation, reseals the same task at the prior commit, and preserves
the original target base. The next worker turn therefore produces a normal
fast-forward correction on the same PR without granting Git access or accepting
task prose as authority. Only the root operator refreshes the protected base,
after an authoritative merged checkout is available.

Publisher acknowledgement is authenticated by the publisher UID and surface
key. `hermes.publisher_ack.v1` binds the canonical repository ID, GitHub host,
owner, name, non-fork status, PR number, remote branch/base/head, newest exact
end-to-end workflow ID/path/event/run/attempt/check suite, every required job ID
and GitHub App ID/slug/head, and a post-CI ready-label event plus exact readback.
The operator pins the CI-check App and the publisher's GitHub actor separately;
the broker therefore does not confuse a successful Actions check with the
distinct no-agent identity authorized to apply the gate label.
Only that verified acknowledgement can finalize the published feature branch
and terminalize the task/run/operation. It cannot advance the protected
repository baseline to an unmerged PR head; that remains an operator-only
post-merge refresh. The same remote evidence is included in the
HMAC-protected `hermes.publisher_completion.v1` receipt.

Recovery reads completion obligations only from the authenticated publisher
RPC. `list_completion_obligations` accepts a repository filter, an immutable
`created_at`/`completion_id` cursor, and a limit from 1 through 100. Completion
receipts are broker-private, tamper-evident, and exact task/run/claim/repository/
branch/base/head/receipt bound; no result-text fallback exists.

Every turn starts the model from an environment allowlist rather than the
controller's or operator's inherited environment. Dedicated-worker dotenv mode
loads only the selected isolated profile; project dotenv, `.op.env`, managed
machine environment, and external secret sources are disabled. It rejects
GitHub credential keys or recognizable GitHub token material before loading the
profile and scans the worker root both before and after the model subprocess.
Git configuration and prompts are disabled explicitly. A failed scan fails the
turn and leaves publishing authority outside the model UID.

## Quiesce and rollback

Rollback establishes an admission cutoff for every mutating controller,
publisher, and operator RPC and waits for exact in-flight zero. It then disables
both KeepAlive labels before bootout, restores both config flags to false, and
positively rereads that both jobs are unloaded and disabled:

```console
sudo python -m hermes_cli.kanban_broker_install rollback \
  --config /private/var/db/hermes-kanban/service.json \
  --operator-config /private/var/db/hermes-kanban/operator/client.json \
  --wait-seconds 30
```

If quiescence cannot be authenticated or work does not drain within the bound,
rollback stops before bootout. Crash/reboot recovery replays broker-owned
dispatch, commit, export, acknowledgement, and completion journals before new
work is admitted.

The authority database carries an exact schema version and exact table-column
manifest. A missing, downgraded, partially upgraded, or unexpectedly enlarged
schema fails broker initialization before recovery or new work. Future schema
changes require an explicit reviewed migration and version advance; ordinary
`CREATE TABLE IF NOT EXISTS` behavior is not accepted as upgrade proof.
