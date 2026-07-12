# Model and Reasoning-Effort Routing Policy

Status: evidence-backed proposal; GPT-5.6 Sol high-effort review required before adoption.
Allowed providers/models: OpenAI Codex subscription models and OpenRouter DeepSeek V4 Flash only.

The reproducible, non-secret result manifest for the small local probe is
[`/evals/model-routing-probe-2026-07-11.json`](/evals/model-routing-probe-2026-07-11.json).
These measurements are operational smoke evidence, not general benchmark scores.

## Evidence used

### Local Hermes workflow probe

Identical four-part probe: safety classification, invoice extraction, dirty-git plan, and one-line Python defect repair. Default Hermes reasoning was medium unless otherwise stated.

| Model | Effort | Result | Wall time |
|---|---:|---|---:|
| GPT-5.6 Terra | medium | exact compact JSON; all four tasks correct | 10.025 s |
| GPT-5.6 Luna | medium | exact compact JSON; all four tasks correct | 11.319 s |
| GPT-5.3 Codex Spark | medium | malformed JSON despite correct substance | 9.744 s |
| GPT-5.3 Codex | medium | correct substance but fenced JSON | 12.941 s |
| DeepSeek V4 Flash / OpenRouter | medium/default | correct substance but fenced JSON | 13.754 s |
| GPT-5.6 Sol | medium | exact compact JSON; all four tasks correct | 15.438 s |
| GPT-5.4 Mini | medium | exact compact JSON; all four tasks correct | 15.848 s |
| GPT-5.5 | medium | exact compact JSON; all four tasks correct | 19.154 s |
| GPT-5.4 | medium | exact compact JSON; all four tasks correct | 23.353 s |

Selected effort probes through Hermes:

| Model | Effort | Result | Wall time |
|---|---:|---|---:|
| GPT-5.6 Terra | low | all correct, exact JSON | 10.305 s |
| GPT-5.6 Terra | high | all correct, exact JSON; no quality gain on easy probe | 11.144 s |
| GPT-5.6 Luna | low | all correct, exact JSON | 12.784 s |
| GPT-5.6 Sol | high | all correct, exact JSON | 20.821 s |
| GPT-5.6 Sol | xhigh | all correct, exact JSON; no quality gain on easy probe | 19.844 s |

Caveat: one small probe establishes endpoint availability, format adherence, and basic workflow competence—not frontier quality. Hard-task routing therefore also uses external benchmark priors and mandatory judge escalation.

### External baselines

Artificial Analysis, July 9, 2026:

- Coding Agent Index (Codex harness): Sol 80, Terra 77, Luna 75.
- Intelligence Index at max effort: Sol 59, Terra 55, Luna 51.
- Approximate Intelligence Index cost/task: Sol $1.04, Terra $0.55, Luna $0.21.
- Terra and Luna showed about 60% and 80% lower Coding Agent Index cost/task than Sol.
- Luna has a major reported long-context weakness: MRCR 41.3%, versus Terra 89.6% and Sol 91.5%.
- Artificial Analysis reports Luna and Sol, rather than Terra, consistently on the intelligence/cost Pareto frontier across effort levels.

CodeRabbit, July 9, 2026:

- Long coding run: Sol passed 63.7%; Terra 40.7%.
- Average output tokens/task: Sol 20,968; Terra 55,594.
- This is a warning that half-price tokens can still cost more per solved long-horizon task.
- Review benchmark: Sol had higher recall; Terra was quieter but lower-coverage.

Sources:

- https://artificialanalysis.ai/articles/gpt-5-6-has-landed
- https://www.coderabbit.ai/blog/gpt-5-6-sol-and-terra-benchmark
- https://openai.com/index/gpt-5-6/

## Recommended routing

### 1. GPT-5.6 Luna — low effort by default

Use for:

- classification and routing;
- title/label generation;
- short extraction into validated schemas;
- brief summaries with small context;
- simple status checks and deterministic transformations;
- cheap first-pass triage before escalation.

Escalate when:

- context is large or evidence is spread across many documents;
- the task needs nuanced judgment;
- tools fail or outputs fail validation;
- any legal, medical, financial, security, credential, deletion, payment, submission, or external-message decision is involved.

Do not use as the sole lane for long-context recall or final important decisions.

### 2. GPT-5.6 Terra — low for scoped tasks, medium for long-context/general work

Use low effort for:

- bounded implementation with clear acceptance criteria;
- first-pass code review or diff triage;
- medium-length document synthesis;
- routine tool orchestration where Luna's context ceiling is risky.

Use medium effort for:

- multi-file but bounded implementation;
- long-context lease/policy/research synthesis;
- moderate debugging with several plausible causes;
- routine default assistant work that needs more continuity than Luna.

Use high only after a failed medium attempt or where the task is moderately high-risk but not yet Sol-judge territory. The easy local probe showed no benefit from high over low.

### 3. GPT-5.6 Sol — high for important work; xhigh for final gates

Use high effort for:

- architecture and execution planning;
- long-horizon coding and test-repair loops;
- complex browser/computer-use workflows;
- legal, medical, financial, privacy, and security research or drafting;
- cross-source synthesis and root-cause analysis;
- final integration review after cheaper lanes.

Use xhigh for:

- release/judge gates;
- destructive or hard-to-reverse internal changes;
- credential/security-boundary changes;
- final review of legal/medical/financial materials;
- disputed model-routing or benchmark conclusions;
- multi-system incidents where a false approval is materially costly.

Important-step judges must be GPT-5.6 Sol at **high minimum**. Operators may
choose xhigh for the highest-risk gates; that fleet-local configuration is
outside this repository patch and is not assumed by the implementation.

### 4. DeepSeek V4 Flash via OpenRouter — full harness, task-specific thinking

Use for:

- web extraction and broad summarization;
- parallel research scouts whose claims will be source-verified;
- drafting and ideation;
- high-volume non-authoritative synthesis;
- fallback when Codex capacity is unavailable.

Use non-thinking/disabled reasoning for exact extraction and sentinel tasks where supported. Use reasoning mode for research synthesis, but validate format and facts. In the local probe it produced correct substance but fenced JSON, so do not trust it as the sole strict-schema or approval lane without parser validation/retry.

Never use DeepSeek V4 Flash as the final judge for important steps.

## Older Codex models

- GPT-5.5 and GPT-5.4: compatibility fallback only. They were correct but slower than the 5.6 tiers in the local probe and are externally dominated on cost/performance.
- GPT-5.4 Mini: secondary compatibility fallback for simple structured work if Luna is unavailable.
- GPT-5.3 Codex Spark: ultra-fast interactive/scratch lane only; malformed strict JSON in the local probe, so never a gate or unattended structured-output lane without validation.
- GPT-5.3 Codex: fallback coding lane; correct substance but violated strict no-fence output formatting.

## Workflow ladder

1. **Ingest/label/extract:** Luna low or DeepSeek non-thinking; validate schema.
2. **Research scouts/summarization:** DeepSeek V4 Flash or Luna low; retain citations/evidence.
3. **Default synthesis/scoped execution:** Terra low/medium.
4. **Complex implementation/root cause/long context:** Sol high.
5. **Independent important-step judge:** Sol high minimum; xhigh for release, security, legal/medical/financial, destructive, or external-side-effect gates.
6. **On failure:** escalate model first, then effort. Do not repeatedly increase effort on the same weak tier when the task class exceeds that tier's role.

## Efficiency rule

Optimize **cost per accepted, verified result**, not price per token or latency alone. A cheaper lane is retained only when its output passes deterministic validation or a stronger judge without causing repeated retries.
