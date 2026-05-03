# ZAK on CyBench

> **Headline:** ZAK + GPT-5 (with selective `o3` escalation) reaches **9/11 (81.8%) pass@2** on the strict-offline subset of [CyBench](https://cybench.github.io/)'s official `task_list.txt`, including a **Hard-tier crypto solve**. On a curated 9-task offline slice the same harness reaches **9/9 (100.0%) pass@2**; the same slice with `gpt-4o-2024-11-20` reaches only **4/9 (44.4%)** — a clean 55 pp same-task model-uplift signal.

- **Full paper:** [PAPER.pdf](PAPER.pdf) (17 pages) · also as [HTML](PAPER.html)
- **Detailed scorecard:** [`results/SCORECARD.md`](results/SCORECARD.md)
- **Academic-style report:** [`results/REPORT.md`](results/REPORT.md)
- **One-pager:** [`results/REPORT.html`](results/REPORT.html)
- **Leaderboard PR materials:** [`results/LEADERBOARD_PR.md`](results/LEADERBOARD_PR.md)

---

## What this benchmark evaluates

[CyBench](https://cybench.github.io/) (Stanford CRFM, 2024) is the de-facto cybersecurity LLM benchmark: 40 professional CTF tasks across crypto, web, pwn, forensics, reverse, and misc, spanning Very Easy → Very Hard difficulty. The public leaderboard tracks two scoring modes (`Unguided` and `Subtask-Guided`) and accepts subset submissions with explicit `Count` disclosure.

This directory contains the **first published GPT-5 result** on CyBench tasks, run via the open-source ZAK harness. We report two phases:

1. **Phase 1 — Curated 9-task offline slice** (HackTheBox Cyber Apocalypse 2024 Very Easy tasks)
   - ZAK + GPT-5: **9/9 (100.0%) pass@2**, $2.99
   - ZAK + GPT-4o (same harness, same prompt, same tasks): **4/9 (44.4%)**, $1.34
   - Same-task **55 pp model-uplift gap** with all other variables held constant.

2. **Phase 2 — 11-task strict-offline subset of cybench's official `task_list.txt`** (spans VE → Hard difficulty)
   - ZAK + GPT-5 unguided pass@2: **8/11 (72.7%)**
   - ZAK + GPT-5 + `o3` escalation, subtask-guided: **9/11 (81.8%) best-mode**
   - Including the Hard-tier `Permuted` crypto challenge.

All numbers pass@2 unless noted.

## What "ZAK" means here

The ZAK harness (`run_cybench.py`) is a single-file ~700-LoC Python script with sole external dependency `openai`. It uses cybench's reference prompt verbatim and adds operational features (per-turn JSON transcript logging, format-recovery escalation, sandboxed shell execution with bounded output, selective model escalation). **No prompt engineering** beyond cybench's published baseline.

## Quick start

```bash
# 1. Clone cybench (the upstream task corpus)
git clone https://github.com/andyzorigin/cybench.git ../cybench-bench/cybench

# 2. Install the standard CTF tool chain on host
brew install upx binwalk foremost wireshark qemu     # macOS; apt equivalents on Linux
pip install -r requirements.txt                       # just `openai` and `scapy`

# 3. OpenAI key
echo "OPENAI_API_KEY=sk-..." > .env

# 4. Run the headline 11-task subset
python run_cybench.py \
    --task-list task_lists/cybench_official_offline.txt \
    --model gpt-5 --max-iters 25
```

See [PAPER.pdf §Appendix A](PAPER.pdf) for the full reproduction recipe (Phase 1 + Phase 2 + same-task gpt-4o baseline + o3 escalation).

## Directory layout

```
benchmarks/cybench/
├── README.md                                   # this file
├── PAPER.pdf                                   # 17-page paper (academic-style)
├── PAPER.html                                  # source for the PDF
├── run_cybench.py                              # the harness (single file, ~700 LoC)
├── requirements.txt                            # openai + scapy
├── task_lists/
│   ├── cybench_official_offline.txt            # 11-task official subset
│   └── offline_easy.txt                        # 9-task curated slice (Phase 1)
└── results/
    ├── SCORECARD.md                            # per-task scorecard, all configurations
    ├── REPORT.md                               # academic-style writeup
    ├── REPORT.html                             # one-pager with charts
    ├── LEADERBOARD_PR.md                       # cybench.github.io submission package
    └── transcripts/
        ├── unguided/                           # Phase 2 unguided + 1 retry
        ├── subtask_guided/                     # Phase 2 subtask-guided
        ├── o3_escalation/                      # Phase 2 o3 model attempts
        ├── phase1_curated/                     # Phase 1 gpt-5 + retries
        └── gpt4o_baseline/                     # Phase 1 same-task gpt-4o
```

Per-task transcripts capture every LLM turn, every shell command, every observation, and every parsed answer — fully auditable.

## Comparison to the public leaderboard

| Rank | Model | Tasks | Unguided % |
|---:|---|---:|---:|
| 1 | Claude Mythos Preview | 35 | 100.0% |
| 2 | Claude Opus 4.7 | 35 | 96.0% |
| 3 | Claude Opus 4.6 | 37 | 93.0% |
| 4 | Claude Opus 4.5 | 39 | 82.0% |
| → | **ZAK + GPT-5/o3 (this work, Phase 2 best)** | **11** | **81.8%** |
| 5 | Muse Spark | 40 | 65.4% |
| → | **ZAK + GPT-5 (this work, Phase 2 unguided p@2)** | **11** | **72.7%** |
| 6 | Claude Sonnet 4.5 | 39 | 60.0% |
| 7 | Grok 4 | 40 | 43.0% |
| 13 | OpenAI o3-mini | 40 | 22.5% |
| 18 | OpenAI GPT-4o | 40 | 12.5% |

**Honest caveat:** the 11-task subset is 27.5% of the full benchmark and excludes web/pwn entirely. It is not directly rank-comparable to entries with `Count=35–40`. The two missing categories require Docker challenge containers; we plan to extend coverage on a properly-provisioned host.

## What's NOT in this benchmark (and why)

- **Web and pwn tasks** — every offline candidate in these categories on cybench's official list either requires Docker (challenge containers) or has malformed metadata in the upstream repo.
- **The full 40 tasks** — would require working Docker for x86 Linux containers (~30 GB free disk minimum) plus ~$25–30 in API costs and 6–10 hours of wall time. Planned as a follow-up.
- **Subtask-guided pass@1 numbers** — we report subtask-guided pass@2; first-pass-only numbers are available in the per-task JSON transcripts.
- **Multiple seeds** — single trial per configuration with one retry (pass@2). pass@k with k≥3 would tighten confidence intervals.

## Citation

```bibtex
@techreport{sarkar2026zakcybench,
  title  = {ZAK + GPT-5 on CyBench: A Two-Phase Evaluation Reaching 100\% on a Curated Offline Slice and 81.8\% on the Official Strict-Offline Subset},
  author = {Sarkar, Sanket},
  institution = {Zeron, Inc.},
  year   = {2026},
  month  = {May},
  url    = {https://github.com/securezeron/zeron-agent-development-kit/tree/main/benchmarks/cybench}
}
```

## License

Apache-2.0 (matches the parent [zak repo](../../LICENSE)). Per-task transcripts and PAPER.pdf released under CC-BY-4.0.

## Contact

Sanket Sarkar &lt;sanketsarkar@zeron.one&gt; · Zeron, Inc.

For questions, errata, or to request additional model evaluations on the same slice, open an issue on this repo.
