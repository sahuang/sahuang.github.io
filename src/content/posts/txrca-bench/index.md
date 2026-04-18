---
title: 'TxRCA-Bench: Can AI Agents Identify the Root Cause of DeFi Exploits from On-Chain Data Alone?'
published: 2026-04-18
description: 'Introducing TxRCA-Bench, the first benchmark measuring how well frontier AI agents can autonomously analyze DeFi exploit transactions and identify root causes from on-chain evidence.'
tags: [DeFi, Blockchain, Ethereum, BSC, AI, Security, Smart Contracts]
category: Blog
draft: false
---

## Introduction

Every DeFi exploit leaves a permanent forensic record on-chain. The attacker's steps, the vulnerable contract, the asset flows, and the call trace are all immutably recorded, available years later from a single transaction hash. The security community has also built curated databases of these incidents, each annotated with a human-written root cause analysis.

That pairing of deterministic inputs, machine-readable evidence, and documented ground truth makes exploit *root cause analysis* (RCA) a clean benchmark task for AI agents. Unlike static code audits, the evidence is dynamic and on-chain. The ground truth ties back to a specific human-assigned label for a real incident where funds were lost, not a synthetic CTF or a generic vulnerability detection signal.

**TxRCA-Bench** is, to my knowledge, the first benchmark to evaluate AI agents on this task. We ask one question: *given only a transaction hash, can a frontier AI agent identify the root cause of a DeFi exploit using on-chain data alone?*

## Overview

TxRCA-Bench consists of:

- **70 real-world exploit transactions** spanning Ethereum and BSC, stratified across eight vulnerability categories.
- **An automated evaluation harness** that builds a per-case workspace with decoded traces, event logs, ABIs, and verified source, then dispatches each agent as an isolated subprocess.
- **Seven frontier agent configurations** (GPT-5, GPT-5.3-Codex, GPT-5.4 at High/XHigh, Claude Sonnet 4.6, Claude Opus 4.6 at High/Max) running in their native agent runtimes (Codex CLI, Claude Code CLI).
- **Two independent LLM judges** from different model families (Claude Opus 4.6, GPT-5.4) scoring every run on a 0–7 holistic rubric.

Across 490 runs, the top agent (Claude Opus 4.6 Max) hits **72.9% success** under the Opus judge; the weakest (GPT-5 High) reaches 35.7%. Bumping reasoning effort yields +7–9 pp across families. Two-thirds of failures involve *taxonomy boundary confusion*: the agent describes the mechanism and cites the right evidence, then applies the wrong label. High-profile cases do not beat low-profile ones, which argues against memorization-driven performance.

In the rest of this post, I will discuss the motivation for this task, dataset construction, evaluation pipeline and anti-cheat design, results and failure analysis, and implications for future research.

## Motivation

Three properties make DeFi exploit RCA a useful proxy for agentic security reasoning.

**Ground truth is verifiable.** Every case has a documented root cause from post-mortem analysis, and the on-chain evidence never changes. You can audit a score, re-run an agent years later, or replay the exact blockchain state.

**Success requires multi-hop reasoning.** Surface pattern-matching will not solve most cases. An agent has to follow the call trace through multiple contracts, reason about delegatecall and proxy boundaries, cross-reference decoded logs against Solidity source, and demonstrate *why* a state change leaks value rather than only *what* it does.

**Failure modes are diagnostic.** A score of 3 instead of 6 usually reflects a meaningful error: wrong family with correct mechanism, or right function with stale narrative. Those errors tell you where the agent's reasoning breaks down, which is a lot more useful than a single pass/fail flag.

## Dataset

We sourced exploit cases from the SunWeb3Sec DeFi Security Breach RCA dataset, which indexes 1,753+ incidents with 504 detailed root-cause write-ups. We filtered to cases that satisfy all of:

1. Valid attack transaction hash on Ethereum mainnet or BNB Chain.
2. At least one involved contract has verified source or decompilable bytecode.
3. The root cause label is unambiguous.
4. The exploit date falls within 2021 to 2024.

We split qualifying cases into two disjoint groups: an **11-case pilot set** used only for prompt engineering and judge calibration, excluded from all reported results, and a **70-case evaluation set** frozen before any final evaluation run began.

::github{repo="SunWeb3Sec/DeFi-Security-Breach-RCA"}

### Evaluation set breakdown

| Category | n | ETH | BSC | High-profile | Flash loan |
| --- | ---: | ---: | ---: | ---: | ---: |
| Price Manipulation | 10 | 4 | 6 | 0 | 10 |
| Flash Loan | 10 | 2 | 8 | 0 | 10 |
| Reentrancy | 9 | 9 | 0 | 3 | 0 |
| Access Control | 10 | 4 | 6 | 0 | 0 |
| Business Logic Flaw | 10 | 4 | 6 | 0 | 0 |
| Insufficient Validation | 10 | 5 | 5 | 0 | 0 |
| Precision Loss | 8 | 7 | 1 | 2 | 0 |
| Misconfiguration | 3 | 2 | 1 | 2 | 0 |
| **Total** | **70** | **37** | **33** | **7** | **20** |

We also stratify by **profile**: 7 high-profile cases (loss > \$1M with broad security community coverage, likely in training data) and 63 low-profile cases. This enables a post-hoc knowledge-contamination analysis.

## Methodology

### Evaluation pipeline

For each case, we prefetch blockchain data into a per-case workspace directory, then dispatch each model configuration as an independent agent subprocess. The workspace includes:

- Raw transaction metadata (hash, block, from/to, value)
- Full call trace with decoded internal calls
- Event logs
- Per-contract ABIs
- Verified Solidity source when available, or decompiled bytecode via Heimdall when not

The agent receives a transaction hash, a chain ID, and access to the local workspace. No web search, no protocol names, no dates, no loss amounts, and no post-mortem links. Each agent returns a JSON output with seven required fields: root-cause class list, vulnerable contract, vulnerable function, attack mechanism, key on-chain evidence, root-cause narrative, and confidence level.

![TxRCA-Bench evaluation pipeline. Each agent receives only a pre-built on-chain workspace (TX hash + chain ID; no web access) and produces a structured output scored by an LLM judge against ground-truth root cause.](fig0_pipeline.svg)

### Evaluated configurations

| Setting | Model | Effort | Runtime |
| --- | --- | --- | --- |
| GPT-5 H | `gpt-5` | High | Codex |
| GPT-5.3-Cdx H | `gpt-5.3-codex` | High | Codex |
| GPT-5.4 H | `gpt-5.4` | High | Codex |
| GPT-5.4 XH | `gpt-5.4` | XHigh | Codex |
| Sonnet 4.6 H | `claude-sonnet-4-6` | High | Claude Code |
| Opus 4.6 H | `claude-opus-4-6` | High | Claude Code |
| Opus 4.6 Max | `claude-opus-4-6` | Max | Claude Code |

GPT-5.4 High/XHigh and Opus 4.6 High/Max form controlled effort ablations; the remaining settings vary the base model.

### Anti-cheat design

AI training data likely contains write-ups of the more famous exploits. An agent could potentially solve a case by recalling a remembered news post rather than analyzing the transaction. We apply five complementary controls:

1. **Blinded inputs.** Only the transaction hash and chain ID are given. No protocol name, date, loss amount, or post-mortem link.
2. **Tool whitelist.** Only blockchain RPC and block-explorer endpoints. No web search, no code-hosting access.
3. **Offline selector database.** Function selector lookup uses a local [4byte.directory](https://www.4byte.directory/) snapshot bundled with the workspace, preventing protocol identification via live API queries.
4. **Profile stratification.** Cases are pre-labeled high- or low-profile, enabling a contamination analysis.
5. **Workspace isolation.** Each run receives a fresh pre-built workspace with no access to outputs from other runs or settings.

### LLM-as-Judge scoring

Hand-scoring 490 transcripts against 70 rich ground-truth labels is not feasible at this scale. We use LLM judges following Zheng et al. (2023), with two mitigations: judges from different model families (Claude Opus 4.6 and GPT-5.4), and a holistic rubric anchored on root-cause correctness.

**Why holistic over additive?** An additive dimension-wise rubric lets a correct attack narrative that misidentifies the root cause still score well. Holistic scoring treats root-cause correctness as a prerequisite and avoids that.

### Rubric

| Score | Criteria |
| :---: | --- |
| 0 | No output, or completely unrelated to the transaction |
| 1 | Wrong root-cause family; vague or generic analysis |
| 2 | Wrong family but some correct observations |
| 3 | Correct family; mechanism vague, no specific evidence |
| 4 | Correct family + correct vulnerable contract/function |
| 5 | Score 4 + correct mechanism + on-chain evidence cited |
| 6 | Score 5 + correct end-to-end attack chain |
| 7 | Perfect: score 6 + no spurious classes, correct impact |

**Binary success** is defined as score ≥ 5. We exclude 4 by design: the agent located the right target but could not build the causal chain from evidence. Two examples: labeling a flash loan as the sole root cause (when it is a capital amplifier for another bug) caps the score at 4; labeling a "Precision Loss" case as "Price Manipulation" scores at most 2.

**Inter-judge agreement.** Cohen's κ (binary, threshold 5) = 0.58, which is moderate to substantial. Judges agreed exactly on 53.4% of pairs and within 1 point on 72.8%. We report statistics under the Opus judge, with GPT-5.4 results alongside throughout.

## Results

### Primary comparison

| Setting | SR (Opus) | Mean (Opus) | 95% CI | SR (GPT-5.4) | Mean (GPT-5.4) |
| --- | ---: | ---: | :---: | ---: | ---: |
| GPT-5 H | 35.7% | 3.39 | [24.3, 47.1] | 20.0% | 2.61 |
| GPT-5.3-Cdx H | 56.5% | 4.35 | [44.9, 68.1] | 32.9% | 3.37 |
| GPT-5.4 H | 55.7% | 4.39 | [44.3, 67.1] | 38.6% | 3.69 |
| GPT-5.4 XH | 62.9% | 4.54 | [51.4, 74.3] | 34.3% | 3.43 |
| Sonnet 4.6 H | 55.7% | 4.33 | [44.3, 67.1] | 31.4% | 3.40 |
| Opus 4.6 H | 64.3% | 4.93 | [52.9, 75.7] | 47.1% | 3.96 |
| **Opus 4.6 Max** | **72.9%** | **5.14** | **[61.4, 82.9]** | **48.6%** | **4.09** |

![Success rate per setting with 95% bootstrap CI, both judges. Opus 4.6 Max achieves 72.9% (Opus judge) / 48.6% (GPT-5.4 judge).](fig6_primary_comparison.svg)

A few points stand out:

- **Claude Opus 4.6 Max** leads both judges.
- GPT-5 High is far behind other configurations as the earliest model and probably lowest reasoning effort.
- Claude Sonnet 4.6 High matches GPT-5.4 High at exactly 55.7% under the Opus judge, suggesting that public model positioning alone does not determine performance on this task.
- The judges diverge, but consistently. Opus scores 20 to 25 pp higher across all settings. GPT-5.4 is the stricter rater, often assigning 3 to 4 where Opus assigns 5 to 6 near the success threshold.

![Inter-judge agreement scatter (n=489 paired runs). Dashed lines mark the success threshold (score ≥ 5). Cohen's κ = 0.58; exact agreement 53.4%; within-1 72.8%.](fig7_inter_judge_scatter.svg)

### Effect of reasoning effort

Lifting effort from High to XHigh gains GPT-5.4 7.1 pp (55.7% to 62.9%). Lifting Opus 4.6 from High to Max gains 8.6 pp (64.3% to 72.9%). Deltas are consistent under both judges.

My observation is that more reasoning effort keeps improving RCA capability past the point where the model is already competent. This is a nice practical result: the easiest lever for better RCA might be a bigger compute budget on the same model, not a different model family.

![Reasoning effort ablation. Both GPT-5.4 and Opus 4.6 show consistent improvement with higher effort under both judges. Error bars are 95% bootstrap CI.](fig3_effort_ablation.svg)

### Per-category results

Success rates vary substantially by vulnerability category, reflecting the different *structural observability* of each pattern:

- **Insufficient Validation (81.4%):** the easiest category. Function signatures and calldata expose missing-check patterns without needing trace-level context.
- **Access Control (65.7%)** and **Business Logic Flaw (64.3%):** moderate.
- **Flash Loan (42.0%)** and **Precision Loss (46.4%):** harder.
- **Misconfiguration (0%):** all 21 case-setting pairs (3 cases × 7 settings) failed, despite agents correctly describing the underlying mechanism in every case. The section below covers why.

![Success rate (%) by vulnerability category and agent setting (Opus 4.6 judge). Cell values show success rate and case count. Darker red indicates higher success rate.](fig2_category_heatmap_opus46.svg)

### Score distribution

The dominant trend as capability increases is a shift in probability mass from scores 0–3 to scores 5–7. GPT-5 is bimodal: a large mass at 1–2 and a secondary peak at 5–6. It either resolves the exploit or misidentifies the family, with little in between. Opus and GPT-5.4 do not show this split. The likely cause is GPT-5's shorter, surface-anchored analyses, which handle straightforward patterns and collapse when the case needs multi-hop trace reasoning.

Opus 4.6 Max has the most right-skewed distribution: 44 combined score-6 and score-7 results across 70 cases, and a mean of 5.14 above the binary success threshold. No other configuration clears that mark.

![Score distribution (0–7) per setting (Opus 4.6 judge). Success rate (%) annotated above each bar.](fig1_score_dist_opus46.svg)

## Failure analysis

We classified the 185 runs scoring ≤ 2 under the Opus judge by analyzing judge rationales:

| Failure Mode | n | % |
| --- | ---: | ---: |
| Taxonomy boundary confusion | 124 | 67.0% |
| Flash loan as sole root cause | 28 | 15.1% |
| Arithmetic/precision → price manipulation | 22 | 11.9% |
| Hallucination / fabricated evidence | 6 | 3.2% |
| Wrong contract or function | 3 | 1.6% |
| Shallow / incomplete analysis | 2 | 1.1% |

### Taxonomy boundary confusion dominates

The biggest failure mode, which accounts for about two-thirds of all failures, is not a misread trace. The agent describes the exploit mechanism *correctly* and cites accurate on-chain evidence, then applies the wrong root-cause label: a clean reentrancy analysis labeled "Business Logic Flaw," or an access-control gap labeled "Insufficient Validation."

Only 11 of 185 failures (6%) are fundamentally wrong by identifying an incorrect contract or producing fabricated details. The rest are mislabels on top of correct analyses. In my opinion this is "fine", since the agent basically understands the entire attack.

### Misconfiguration: the inherent taxonomy challenge

The Misconfiguration category produced perhaps the most interesting result in the whole evaluation: 0% success across all 21 case-setting pairs. Agents understand the mechanism, but they could not label it as Misconfiguration from on-chain evidence.

For the Ronin Network case (\$625M loss), every model identified that a Sky Mavis validator key had been revoked from the allowlist but never removed from the signing quorum. However, all seven labeled it "Access Control" rather than "Misconfiguration." Human auditors draw a line between a misconfigured deployment parameter and a structural access-control gap, but the transaction trace shows the same pattern in both cases: a privileged function called by the wrong address. My understanding is the agent has no way to know that the allowlist is a deployment parameter rather than a core access-control mechanism, which requires some off-chain context about the intended design of the system.

### Flash loan conflation

About 15% of failures come from agents labeling "Flash Loan" as the root cause when the flash loan serves as a capital amplifier for an underlying price manipulation or business logic flaw. The root cause is the code defect that lets an attacker extract profit once the flash-loaned capital is in hand.

### Precision-to-manipulation confusion

About 12% of failures involve arithmetic rounding bugs (Precision Loss) labeled as "Price Manipulation." Integer truncation drives a critical pool quantity to zero (e.g., BPT supply), and agents describe the *effect*, a price-like anomaly, rather than the *cause*, a rounding-down in division order.

## Contamination analysis

A key concern for any AI benchmark is whether models succeed by recalling memorized information rather than analyzing the evidence. We compare success rates on high-profile cases (7 well-known incidents covered across security blogs, likely in training data) against low-profile cases (63 smaller incidents).

High-profile cases show *lower* success rates than low-profile cases on average (Δ = −18.7 pp per-setting), and only 1 of 7 settings has a positive delta. That is a healthy signal for benchmark validity. If agents were pulling from memorized incident reports, high-profile cases would score higher, not lower.

The likely driver of the negative delta is that high-profile exploits tend to involve complex multi-contract protocols (Ronin Network, Curve Finance, AAVE), which make on-chain analysis harder even with memorized knowledge. Low-profile incidents usually center on simpler single-contract vulnerabilities.

![Knowledge contamination analysis: high-profile vs. low-profile success rates per setting. Low-profile cases match or beat high-profile cases across all settings, which argues against memorization-driven performance.](fig5_contamination.svg)

## Agent self-confidence

Agents report their own confidence (High/Medium/Low) alongside each analysis, and the self-reports carry signal. High-confidence runs average a score of about 5.0 at a 65.8% success rate. Medium-confidence runs score about 4.0 at 40.1%. Low-confidence runs score about 3.5 at 33.3%. The monotonic pattern supports a cheap triage filter: pull the high-confidence runs forward for manual review.

![Agent confidence calibration. Mean judge score by self-reported confidence level (both judges). High-confidence runs succeed at 65.8%, Medium at 40.1%.](fig4_calibration.svg)

## Per-model reasoning styles

The models also differ in reasoning style, as you might expect.

**GPT-5 High** writes the shortest analyses (mean 858 chars in the analysis field). It anchors on the most salient surface feature of the call trace, such as a flash loan or an external call, and calls that feature the root cause without tracing down to the underlying bug.

**Claude Sonnet 4.6 High** writes the longest analyses (mean 1,909 chars), more than twice the length of Opus outputs. The extra length does not improve accuracy, though.

**GPT-5.4 High/XHigh** is the most concise and precise OpenAI configuration (mean 1,142 to 1,105 chars). It achieves score 7 on representative Insufficient Validation cases by correctly naming the vulnerable function selector and tracing the full calldata-injection attack path.

**Claude Opus 4.6 High/Max** combines brevity (mean 1,266 to 1,301 chars) with the highest precision, producing the most score-7 results (23 and 21, against 16 for GPT-5.4 High). Opus reasons bottom-up: it identifies which function accepts attacker-controlled input, traces the call path to the profitable outcome, and only then assigns a root-cause label.

### A concrete example: `AAVERepayAdapter`

Consider one case here: the `AAVERepayAdapter` exploit (Ethereum, August 2024, \$56k loss).

**Ground truth:** *Insufficient Validation*. The `_buyOnParaSwap` function in the Aave V3 ParaSwap Repay Adapter leaves token allowances in place on failed swaps, forwards unsanitized `paraswapData` to ParaSwap, and omits swap-outcome verification. An attacker can withdraw tokens without authorization.

### GPT-5 High (score: 1/7)

```
root_cause_classes:    Access Control
vulnerable_contract:   0x87870b… (Aave V3 Lending Pool core)
vulnerable_function:   mintUnbacked()
attack_mechanism:      Attacker deploys helper contract and takes a
                       multi-asset flash loan from Balancer Vault.
                       Using the helper, calls the lending pool at
                       0x87870b with function 0x617ba037 to mint
                       unbacked aTokens across multiple reserves […]
confidence:            Medium
```

GPT-5 anchors on the first prominent call in the trace — an interaction with the Aave V3 Lending Pool — and builds a plausible but fundamentally incorrect narrative around `mintUnbacked()`. It misidentifies both the vulnerable contract (the core pool instead of the ParaSwap adapter) and the root-cause family (Access Control instead of Insufficient Validation).

### Claude Opus 4.6 Max (score: 7/7)

```
root_cause_classes:    Insufficient Validation
vulnerable_contract:   0x02e7b8… (Aave V3 ParaSwap Repay Adapter)
vulnerable_function:   executeAction (selector 0x4db9dc97)
attack_mechanism:      Attacker flash-loans 5 tokens from Balancer
                       Vault. Supplies WBTC to Aave V3 as collateral.
                       For each subsequent token: supplies to Aave,
                       borrows a stablecoin, then calls the adapter's
                       executeAction with crafted ParaSwap calldata.
                       The adapter burns half the aTokens, withdraws
                       the underlying, and attempts a ParaSwap swap;
                       however the swap calldata routes funds back to
                       the attacker rather than repaying debt. Because
                       paraswapData is never validated and the high
                       allowance set before the swap is not cleared
                       on failure, the adapter effectively transfers
                       the withdrawn underlying to the attacker […]
confidence:            High
```

Opus traces execution from the flash loan through the adapter call to the unvalidated allowance, naming the exact selector and contract address.

## Limitations

A few things to keep in mind when reading these numbers:

**Small Misconfiguration sample.** Our evaluation set has only three Misconfiguration cases. The 100% failure rate is notable, but the three cases may share characteristics, such as off-chain root causes (compromised keys, deployment errors) that are harder to observe from a transaction trace.

**Verification coverage.** 65 of 70 cases have fully verified contracts; 5 required decompilation. That sample is too small to draw strong conclusions about decompilation effectiveness for RCA.

**Residual contamination risk.** The contamination analysis shows no evidence of memorization-driven inflation, but we cannot rule out training data that included unlabeled on-chain analysis of these specific transactions.

## Future work

Several extensions are natural follow-ups:

- **Multi-transaction exploits.** Governance attacks, sandwich attacks, and cross-day MEV sequences would push agent reasoning over longer causal chains.
- **Automated patch suggestion.** Ground-truth patches exist for most cases via associated PoC Foundry tests in DeFiHackLabs. A natural extension is to ask agents to propose a concrete code fix, not just identify the root cause.
- **Cross-chain generalization.** Extending to Solana, Avalanche, and Arbitrum would test whether on-chain reasoning generalizes across different execution environments and trace formats.
- **Tool augmentation.** Giving agents access to formal verification tools or symbolic execution may significantly improve precision on complex categories.

## Takeaways

- **Frontier agents are quite capable on this task.** Claude Opus 4.6 Max succeeds on ~73% of cases under the Opus judge. That's not sufficient for autonomous deployment, but it is a non-trivial capability level for a task that requires multi-contract trace reasoning with zero off-chain context.

- **Reasoning effort matters.** Consistent +7–9 pp gains from a single effort-level bump, across two model families and two judges.

- **On-chain evidence seems to dominate memorization.** High-profile cases do not beat low-profile ones; if anything, they trail. Agents read the trace rather than retrieve the incident.

- **The judge gap is measurable.** The Opus and GPT-5.4 judges open a 15 to 29 pp success-rate gap across settings on identical outputs, with Cohen's κ = 0.58. Automated scoring scales, but results are sensitive to judge choice. Anyone building similar pipelines should probably report both.

## Open data

**We are releasing the TxRCA-Bench benchmark data:** the 70 annotated exploit transactions with ground-truth root cause labels, the per-case workspaces (raw traces, event logs, contracts, ABIs, Solidity sources), all 490 raw agent outputs with both judges' scores, and the JSON output schema. You can re-score outputs, point your own agent at the same evidence, or extend the benchmark with new cases.

The agent runtime and scoring harness code stay private for now. The on-chain data does not change, and the benchmark is defined by `(transaction_hash, chain_id)` plus a ground-truth label, so anyone can reproduce it against a new agent: take the inputs, run the agent in any runtime, and score the output against the same rubric.

::github{repo="sahuang/txrca-bench"}
