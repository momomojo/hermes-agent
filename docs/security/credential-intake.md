# Credential Intake Links

Credential intake links are a Hermes-native scaffold for asking a local user to
provide a secret without putting that secret in chat, task comments, logs, or a
model-readable file.

The flow is intentionally conservative:

- `hermes credential-intake create` creates a short-lived one-time token.
- Hermes stores only the token hash, destination metadata, TTL, and status.
- The generated URL is localhost-only and carries the bearer token in the URL
  fragment (`#token=...`), not the query string.
- `hermes credential-intake submit` consumes the token once and passes the
  submitted value to a scaffold adapter.
- Current adapters do not persist submitted secrets. They only validate the
  intended destination shape for future explicit integrations.

Example:

```bash
hermes credential-intake create \
  --adapter profile-env \
  --key OPENAI_API_KEY \
  --label "OpenAI API key for default profile" \
  --ttl 15m
```

Then submit locally:

```bash
hermes credential-intake submit '<local_url>'
```

For non-interactive tests or local automation, pipe the value through stdin:

```bash
printf '%s' "$VALUE" | hermes credential-intake submit '<local_url>' --value-stdin
```

Do not pass real secrets as command-line arguments. Shell history and process
lists can expose arguments. The command deliberately has no `--value` option.

## Destination Adapters

`profile-env` accepts an environment variable name such as `OPENAI_API_KEY`.
It does not write `~/.hermes/.env`.

`onepassword` accepts `--vault`, `--item`, and `--field` labels. It does not
call the `op` CLI or modify a vault.

Future real adapters should keep the same token semantics: TTL, single use,
localhost-only submission, no secret echo in receipts, and no secret-bearing
log messages.
