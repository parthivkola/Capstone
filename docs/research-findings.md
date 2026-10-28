# Preserved research findings and provenance status

**Scope:** this summary records reported offline findings for project review. It does not recompute experiments or upgrade historical claims. Research protocol: [`research-protocol.md`](research/research-protocol.md). Study result files are under `experiments/stage5b` through `stage5f`, with associated scripts and reports under `scripts/`, `ml/`, and `docs/research/dataset-audit/`.

## Artifact-preservation check

Before implementation, SHA-256 hashes were recorded for 160 files across `docs/research`, `docs/architecture`, `experiments`, and `data` in `/tmp/capstone-frozen-before.sha256`. The manifest is outside the project tree. The after-check is reported in the review handover. Counts and metrics below remain “previously reported”; hash equality establishes byte preservation in this pass, not independent scientific replication.

## Dataset audit (previously reported)

| Dataset | Reported audit |
|---|---|
| CIC-IDS2017 | 2,830,743 rows; 5,734 nonfinite values; 256,479 within-file duplicates |
| CSE-CIC-IDS2018 | 16,233,002 rows; 191,520 nonfinite values; 410,763 duplicates. The 20-Feb source has four extra endpoint fields; three files contain repeated headers. |
| UNSW-NB15 | 2,797,720 rows; 6,426,667 missing cells. Official train/test parsed rows reportedly had no exact shared rows. |
| TON_IoT | 211,043 rows. Provenance is incomplete: one Hugging Face mirror CSV, not the complete processed collection. |

## Offline classifier results (previously reported)

- UNSW Random Forest: accuracy `0.674124`, macro F1 `0.487591`, benign FPR `0.412568`.
- CSE-CIC-IDS2018 source holdout A: accuracy `0.995351`, custom macro F1 `0.259719`, supported macro F1 `0.519438`, benign FPR `0.004384`, attack FNR `0.409894`.
- Holdout B: accuracy `0.990413`, custom macro F1 `0.199560`, supported macro F1 `0.399120`, benign FPR `0.009510`, attack FNR `0.138122`.
- Unseen LOIC-HTTP: accuracy `0.907355`; macro F1 on two supported test labels `0.475739`; benign FPR `0.021156`; attack FNR as benign `0.998631`. Of 576,191 LOIC-HTTP examples, 575,402 were predicted benign.

These results show why accuracy alone is insufficient. They are not evidence of live rule-counter detection.

## Novelty/open-set results (previously reported, weak)

- Isolation Forest at a 1% validation benign-FPR target produced test benign FPR `1.079%` and unknown recall `0`.
- At a 5% target, LOIC-HTTP unknown recall was `0.122008%`, precision `0.138529%`, F1 `0.001297`.
- RF confidence open-set rejection: LOIC unknown recall `0.053628%`, precision `0.321550%`, unknown F1 `0.000919`, balanced accuracy `0.493719`.

These do not support a claim of reliable unknown-attack detection.

## Source/distribution shift (not temporal drift)

The prior study used initial training from three February dates, binary benign/attack labels, and deterministic SHA-256 70/15/15 partitioning. PSI signaled at least five features in all 20 evaluation windows, with no initial-validation triggers. Periodic updates had window-4 macro F1 `0.508761 ± 0.002476` and attack FNR `0.928177`; PSI-triggered updates had macro F1 `0.570637 ± 0.005778` and attack FNR `0.097238`. Paired macro-F1 difference was `+0.061876` (CI `[0.056699, 0.067052]`); FNR was lower by `0.830939`.

PSI triggered constantly, so the result does not establish a selective/reliable trigger. The source ordering and provenance do not establish temporal or concept drift. The result remains a source/distribution-shift experiment only.

## Verification labels

The result JSON and report files listed above are present in the workspace and their bytes were included in the pre-edit frozen hash manifest. Metrics in this document are transcribed from the supplied historical findings and existing research reports, not recomputed during application implementation. Before making a new publication claim, reconcile every metric with the exact run artifact, protocol and source manifest. Preserve negative results and all caveats.
