# Architecture

```
Browser UI (vanilla ES modules, no build) ──HTTP/JSON, 127.0.0.1 + session token──► api/server.py (stdlib)
                                                                                      │
                                                                               app.py (container)
        ┌──────────────┬──────────────┬───────────────┬──────────────────┬────────────┴───────────┐
     shield/        vision/        sentinel/      inference/          response/                 ai/
 scanner,defender  pii,extract,   analyzer       engine (rules →     service (actions,      provider
 quarantine        analyze                        graph)              confirmation, audit)   (Ollama)
        └──────────────┴──────────────┴──── core/: models · masking · db · audit · config · log ─────┘
```

* **Only `core` is shared.** Analyzers never import each other; they communicate through `Finding`/`Entity` records in SQLite.
  This is what lets the graph connect a phishing message to a screenshot without either module knowing about the other.
* **Findings are the contract** (`core/models.py`). Invariants are enforced in code: evidence is mandatory; a finding's tier is the
  weakest of its evidence; evidence produced by `ai:*` can never exceed `ai_assessed`.
* **Entities** are stored as `(kind, masked display, salted SHA-256)`. Two sources "match" when hashes match. Raw values are never persisted.
* **Inference** is deterministic and re-runnable: finding ids are hashes of (rule, entities, sources), so re-running keeps your resolved status.
* **Response** is the only state-changing layer. Every action: listed with its description → confirmation if it touches files → recorded in `actions` and the hash-chained `audit_log`.

## Deliberate engineering decisions (deviations from the earlier plan, and why)

| Decision | Reason |
|---|---|
| Standard-library HTTP server + SQLite instead of FastAPI/Pydantic | Build environment had no network, so FastAPI could not be installed or verified. Stdlib also removes install risk on the demo laptop. Dataclasses enforce the same schema. Porting to FastAPI later is mechanical (`api/server.py` only). |
| Vanilla JS modules instead of React/TypeScript | Same reason; no build step, nothing to break on demo day. Components are small functions in `web/js/ui.js`. |
| Own SVG force layout instead of Cytoscape.js | No network for npm. Adequate for ≤ ~50 nodes; Cytoscape is the upgrade path for larger graphs. |
| Regex + validators instead of Presidio/spaCy NER | Explainable per-rule evidence and zero model downloads. Cost: no unlabelled-name detection. |
| Minimal PE parser instead of `pefile`/YARA | Not installable offline. Detections are limited to header/section indicators; YARA is the upgrade path. |

## Extensibility toward hardware-backed components
Analyzers emit `Finding`s with a `module` and `produced_by`; a future hardware attestation or TPM-backed signal would be a new
analyzer producing `verified`-tier evidence. No hardware is claimed or simulated in this version.

## Threat model highlights
Hostile files (parsers are size-capped, nothing is executed), hostile messages (rendered via `textContent` only; LLM input is wrapped and
schema-validated; injection phrases are themselves an indicator), hostile web pages (no CORS, token, Host check, CSP, `nosniff`),
local tampering (hash-chained audit log; vault integrity check before restore).
