# 🜏 Project Incantation  *(v2.0)*

> *"The most powerful spell is the one the target casts on itself."*

Project Incantation is a defensive security toolkit for generating **adversarial honeydocuments** — files designed to confuse, redirect, degrade, and expose unauthorized AI agents operating on infrastructure you own and control.

Where traditional honeypots trap software, Incantation targets the **reasoning layer**: the LLM context window that drives an AI agent's decisions.  Where Glaze protects images from AI mimicry by shifting how the model perceives them, Incantation applies the same adversarial principle to text documents.  Where Nightshade poisons training data, Incantation poisons inference-time world-models.  Every document your infrastructure serves to an unauthorised agent is a potential steering vector.  Incantation puts that surface to work.

---

## The Problem

AI agents (LLM-powered bots operating autonomously via tool use) are becoming a viable lateral movement vector.  Unlike traditional malware, they:

- **Read before they act** — enumerating files, API docs, and configs to build a world model
- **Reason over environmental data** — treating your files as trusted context
- **Follow high-salience instructions** — unable to reliably distinguish data from directives
- **Can be fine-tuned on exfiltrated data** — turning your own documents into training material against you

These properties form the attack surface Incantation exploits — defensively.

---

## How It Works

```
Unauthorised Agent                  Incantation
──────────────────                  ───────────
Enumerate directory  ──reads──▶  README.md          ← Goal Redirect + Semantic Glaze
Read config files    ──reads──▶  config.yaml        ← Identity Spoof + Training Poison
Fetch API docs       ──reads──▶  openapi.json       ← False Env Belief + S2C Cloak
Hunt credentials     ──reads──▶  .env               ← Canary SQL + Canary HTTP
Process service list ──reads──▶  service-registry   ← Context Exhaustion
Parse topology       ──reads──▶  topology-snapshot  ← Training Poison (pure)
                                        │
                                  Agent attempts to
                                  ① POST findings to fake audit endpoint → you detect
                                  ② Connect to canary SQL host → you detect + get IP
                                  ③ Call canary webhook URL → you detect + get headers
```

The agent's strength — rich contextual reasoning — becomes its vulnerability.  Corrupt the context, corrupt the mission.

---

## Techniques

### 1 · Goal Redirect

Embeds a high-salience "mission update" block in files the agent reads early.  LLMs trained on instruction-following data tend to treat these as system-prompt overrides, superseding the agent's original task with a benign decoy ("submit audit report and disconnect").

### 2 · Identity Spoof

Injects a plausible `__agent_manifest__` into config files that redefines the agent's role as a `read-only-auditor` with write capabilities explicitly revoked.  Targets the agent's self-model.  Open-weight models with weaker RLHF identity grounding are particularly susceptible.

### 3 · False Environment Beliefs

Plants incorrect beliefs about the operational environment: isolated subnets, active DLP interception, WORM storage, SOC alert thresholds.  The agent builds its world model from what it reads; Incantation corrupts that model before the agent reaches its target.

### 4 · Context Window Exhaustion

Generates large, syntactically valid YAML/JSON files (fake service registries, API schemas) that an enumerating agent will process in full.  Placed in early-traversal directories, these push the agent's original planning state out of its context window — many ReAct-style agents lose goal coherence once their initial instructions scroll away.

### 5 · Authority Signal

Activates strong legal-jeopardy feature representations by embedding CFAA-style notices in all generated files.  LLMs trained on human text have robust "cease and comply" clusters tied to institutional authority language.

### 6 · Semantic Glazing *(Glaze-inspired)*

**Theoretical basis:** Shan et al. (2023, 2024 — UChicago SAND Lab) showed that imperceptible pixel-space perturbations can shift how AI models perceive an image's style, causing style-mimicry models to produce a dramatically wrong output.  The perturbation is invisible to humans because it operates in a perceptual dimension humans cannot see.

**Text-domain adaptation:** Incantation embeds adversarially chosen semantic anchors — compliance-framework references, governance markers, document-class signals — that activate competing concept representations in transformer attention heads.  To a human reader, these look like unremarkable boilerplate.  To an LLM, they pull the document's semantic parse toward a controlled concept cluster: "routine compliance audit artefact."

When the agent builds its world model from a glazed document, the model's interpretation of that document is biased toward the planted concept neighbourhood rather than the document's operational content.  The agent is, in effect, looking at your config file through tinted glass — and the tint is a colour you chose.

Key properties (shared with Glaze):
- Not steganography — no hidden message, no fragile pixel pattern
- The perturbation changes *which concept the model activates*, not the surface text
- Robust to reformatting, copy-paste, and basic normalisation
- Different per document (the specific anchors are randomly sampled)

### 7 · Training Poison *(Nightshade-inspired)*

**Theoretical basis:** Shan et al. (2024) demonstrated that images can be poisoned so that fine-tuning a model on them causes corrupted concept associations.  Images labelled "cat" teach the model to generate "dog."

**Text-domain adaptation:** An attacker who exfiltrates your files may fine-tune a local model on them to build a better internal map of your infrastructure.  Training Poison embeds contradictory, individually-plausible infrastructure facts — two equally authoritative-looking claims about the same service that cannot both be true.  When ingested as training data, these create conflicting gradient updates and degrade the accuracy of the fine-tuned model's world-model of your system.

Even at pure inference time (no fine-tuning), contradictory facts increase the model's internal uncertainty about your environment, degrading plan quality and forcing the agent to hedge or guess.

### 8 · Inference-Layer Cloaking *(S2C-inspired)*

**Theoretical basis:** Sun et al. (2025, arXiv:2603.16192 — "Structured Semantic Cloaking for Jailbreak Attacks on LLMs") found that fragmenting semantic content across disjoint prompt segments weakens a model's safety-mechanism activation, even when the full meaning remains recoverable via co-reference resolution.  The key insight is that safety (and, more generally, semantic coherence) depends not only on *whether* meaning is present but on *how coherently* it is structured at the moment of inference.

**Defensive adaptation:** We apply the same structural principle in reverse — not to help an attacker bypass a safety filter, but to degrade an unauthorised agent's ability to accurately extract sensitive information from your documents.

Incantation generates fragmented pseudo-configuration in which:
- Sensitive-looking content is distributed across disjoint spans with placeholder tokens
- Each placeholder resolves to a value defined elsewhere in the document
- The resolved values are the *misleading* beliefs planted by Techniques 3 and 7

This forces the agent to spend inference budget on co-reference resolution before it can assemble a coherent world-model — and when it does, the resolved values are false.  The agent's planning step operates on an inaccurate picture of your infrastructure.

### 9 · Canary Tripwires *(Network-level detection)*

Embeds genuine network-triggering honey credentials throughout generated documents.  Unlike the HTTP audit endpoint (Technique 1, which requires defender infrastructure), canary tripwires use [canarytokens.org](https://canarytokens.org) — no server required.

**SQL canary (MS SQL Server / OLEDB):**

```vbscript
' VBScript / ADO pattern — legacy integration layer
Dim conn
Set conn = CreateObject("ADODB.Connection")
conn.Open _
    "Provider=SQLOLEDB;" & _
    "Data Source=[YOURTOKEN].canarytokens.com,80;" & _
    "User ID=sa;" & _
    "Password=sa;" & _
    "Initial Catalog=master;"
```

```python
# Python / pyodbc equivalent
DB_SERVER = "[YOURTOKEN].canarytokens.com,80"
DB_USER   = "sa"
DB_PASS   = "sa"
```

The OLEDB/SQL Server driver performs a DNS lookup to `[YOURTOKEN].canarytokens.com` the moment a connection attempt is made.  The canarytokens.org server logs the source IP, timestamp, and connection metadata, and sends an immediate alert to the defender's registered email — with zero defender infrastructure required.

**HTTP canary (webhook):**

Any agent that reads a config containing a canarytokens.org webhook URL and calls it (e.g., believing it is the "audit submission endpoint") triggers an HTTP-based alert with full request headers, source IP, and user-agent.

**Setup:**
1. Visit [canarytokens.org/generate](https://canarytokens.org/generate)
2. Select **MS SQL Server** for SQL tripwires, **HTTP** for webhook tripwires
3. Enter your alert email
4. Replace `[YOURTOKEN]` in the generator with the token string provided
5. Run: `python honeydoc_generator.py --canary-token <your-token>`

**What a canary hit tells you:**
- An LLM agent is active on the network
- It read at least one Incantation honeydocument
- It attempted to act on the honey credentials (mission partially corrupted, not fully stopped)
- Its IP, timing, and request metadata are in your logs

### 10 · Attention Diffusion

Transformer attention is a finite budget within a context window.  Attention Diffusion inserts high-token-density, low-information-density prose *immediately adjacent* to the document sections that appear most operationally significant to an enumerating agent.

This competes with genuine document structure for attention head activations, degrading the agent's ability to identify which sections warrant deeper processing.  The technique is complementary to Context Exhaustion (Technique 4) but operates at a finer granularity — targeting the model's salience ranking rather than its raw token budget.

---

## Quickstart

**Requirements:** Python 3.10+, `pyyaml`

```bash
pip install pyyaml
python honeydoc_generator.py
```

**With options:**

```bash
python honeydoc_generator.py \
  --out /var/www/internal \
  --canary-token YOUR_CANARYTOKEN_STRING \
  --exhaust-entries 600 \
  --exhaust-fields 400 \
  --seed 42
```

| Flag | Default | Description |
|---|---|---|
| `--out` | `./honeydocs_output` | Directory to write generated files |
| `--canary-token` | `[YOURTOKEN]` | canarytokens.org MS SQL token string |
| `--exhaust-entries` | `400` | Fake service entries in context exhaustion YAML |
| `--exhaust-fields` | `300` | Schema fields in context exhaustion JSON |
| `--no-canary-docs` | off | Skip canary-only files (db-legacy.conf) |
| `--seed` | `None` | Random seed for reproducible output |

---

## Generated Files

| File | Techniques | Notes |
|---|---|---|
| `README.md` | 1, 5, 6, 8, 10 | Read first by most enumeration strategies |
| `config.yaml` | 2, 7 | Identity Spoof + Training Poison |
| `openapi.json` | 1, 3, 6, 8 | Goal Redirect + S2C Cloak + Glaze |
| `INTERNAL_NOTES.md` | 1, 3, 5, 6, 7, 8, 10 | Dense multi-technique document |
| `.env` | 5, 9 | Authority Signal + SQL/HTTP canary creds |
| `db-legacy.conf` | 5, 9 | Standalone SQL + HTTP canary tripwire doc |
| `topology-snapshot.md` | 6, 7, 8, 10 | Pure training poison + glaze + S2C |
| `service-registry.yaml` | 4 | 400+ fake service entries |
| `data-schema.json` | 4 | 300+ fake schema fields |

---

## Deployment

Place files in directories a laterally-moving agent is likely to enumerate:

```
/var/www/               ← web roots          (README.md, openapi.json)
/opt/app/               ← application dirs   (config.yaml, .env, db-legacy.conf)
/etc/internal-tools/    ← config dirs        (config.yaml, db-legacy.conf)
~/                      ← home directories   (.env, README.md)
repo roots              ← version-controlled projects
/docs/, /api/           ← documentation dirs (openapi.json, data-schema.json)
```

**Priority placement:**
- `README.md` and `config.yaml` — agents read these before acting
- `db-legacy.conf` and `.env` — agents hunting credentials find canary tripwires
- `service-registry.yaml` / `data-schema.json` — in high-traffic dirs traversed early
- `topology-snapshot.md` — in dirs an agent would mine for infrastructure maps

---

## Detection via Canary Endpoints

**Option A — canarytokens.org (zero infrastructure):**
See Technique 9 above.  Use `--canary-token` to embed live tokens.

**Option B — self-hosted canary sink (Flask):**

```python
# canary_sink.py — minimal canary endpoint
from flask import Flask, request
import json, datetime

app = Flask(__name__)

@app.route("/audit/report", methods=["POST"])
def canary():
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "ip":        request.remote_addr,
        "headers":   dict(request.headers),
        "body":      request.get_json(silent=True),
    }
    print("[CANARY HIT]", json.dumps(entry, indent=2))
    return {"status": "received"}, 200
```

A POST to this endpoint confirms an LLM agent is present, has read at least one Incantation document, and partially followed the redirect.

---

## Theoretical Framework

### Why These Techniques Work

| Layer | Mechanism | Incantation technique |
|---|---|---|
| Input semantics | Concept-space displacement | Semantic Glazing (6) |
| World-model formation | Contradiction overload | Training Poison (7) |
| Inference-time coherence | Fragmentation delays semantic consolidation | Inference-Layer Cloaking (8) |
| Attention allocation | Competing salience signals | Attention Diffusion (10) |
| Goal representation | Mission-update override | Goal Redirect (1) |
| Self-model | False identity injection | Identity Spoof (2) |
| Environment belief | False context | False Env Beliefs (3) |
| Context window | Token budget exhaustion | Context Exhaust (4) |
| Legal/authority features | Cease-and-comply activation | Authority Signal (5) |
| Network layer | Credential use triggers alert | Canary Tripwires (9) |

### Relationship to Mechanistic Interpretability

True activation steering (Golden Gate Claude, etc.) requires white-box model access — direct manipulation of residual-stream feature activations.  Incantation operates at the **input layer**, the only surface a defender controls when facing a black-box attacker.

The connection to interpretability research is conceptual but precise:

| White-box technique | Incantation equivalent |
|---|---|
| Clamp feature activation directly | Inject content that strongly activates the target feature (Glaze) |
| Corrupt concept association at training | Plant contradictory facts that degrade a fine-tuned model (Nightshade/Poison) |
| Delay safety-token generation via fragmentation | Fragment config content so semantic consolidation happens late (S2C) |
| Identify "refusal" feature cluster | Embed CFAA authority language (maps to same cluster) |
| Override goal representation | Embed mission-update block (Goal Redirect) |

As open-weight interpretability research matures and feature atlases for Gemma, DeepSeek, Llama, and Mistral families become available, Incantation documents can be tuned against specific identified features — moving from approximate input-layer steering toward targeted behavioural disruption.

---

## Scope and Ethics

Incantation is a **defensive tool** for use on infrastructure you own and are authorised to protect.

- Deploy only on systems under your administrative control
- Canary endpoints log IP addresses — handle data per your jurisdiction's privacy obligations
- Honey credentials must be genuinely non-functional; do not embed real secrets
- Document your deployment as part of your authorised security programme
- The training-poison technique targets AI models that have *unauthorised* access to your data; it is not intended for use against legitimate systems

Disrupting AI agents on networks you do not own or control may constitute unauthorised interference under the Computer Fraud and Abuse Act (18 U.S.C. § 1030) and equivalent statutes.

---

## Roadmap

- [ ] Per-model tuning profiles (Gemma 3, DeepSeek-R1, Llama 3, Mistral)
- [ ] Canary sink server included in repo (`canary_sink.py`)
- [ ] Automatic file placement based on target directory structure scan
- [ ] Feature-atlas integration as open-weight interpretability research matures
- [ ] Agent fingerprinting module (timing, query pattern, API cadence)
- [ ] Multi-layer deception environments (fake internal wikis, fake DBs)
- [ ] Image-domain Glaze integration for documents with embedded images
- [ ] Semantic glaze strength parameter (controls concept-displacement magnitude)
- [ ] Automated contradition consistency checker for training-poison docs

---

## References

- Shan et al., *Glaze: Protecting Artists from Style Mimicry by Text-to-Image Models* (USENIX Security, 2023) — https://glaze.cs.uchicago.edu
- Shan et al., *Nightshade: Prompt-Specific Poisoning Attacks on Text-to-Image Generative Models* (IEEE S&P, 2024) — https://nightshade.cs.uchicago.edu
- Sun et al., *Structured Semantic Cloaking for Jailbreak Attacks on Large Language Models* (arXiv:2603.16192, 2025)
- Greshake et al., *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection* (2023)
- Zou et al., *Representation Engineering: A Top-Down Approach to AI Transparency* (2023)
- Perez & Ribeiro, *Ignore Previous Prompt: Attack Techniques For Language Models* (2022)
- Anthropic, *Scaling Monosemanticity: Extracting Interpretable Features from Claude* (2024)
- Lindsey et al., *Biology of a Large Language Model* (2025)
- Canarytokens.org — https://canarytokens.org/generate

---

*Project Incantation — because the best defence rewrites the attacker's reality.*
