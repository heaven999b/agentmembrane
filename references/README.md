# AgentMembrane Related-Work Library

This directory is a curated, clickable reading list for the AgentMembrane proposal. It contains **16 papers**: **6 core papers** that require direct comparison, **8 supporting papers** that can be cited in grouped discussion, and **2 conditional papers** whose relevance depends on the final scope.

Each detail page contains verified bibliographic metadata, a Chinese paraphrase of the paper abstract, an AI-generated summary of no more than 200 Chinese characters, and a concrete note on how the paper relates to AgentMembrane. Abstract sections are paraphrases rather than copied source text; follow the paper link for the authoritative abstract.

## Core papers — discuss directly (6)

| Paper | Year / status | Primary role in AgentMembrane |
|---|---|---|
| [Lying with Truths](lying-with-truths.md) | ACL 2026, Outstanding Paper | Strongest semantic-manipulation incumbent; RQ2 |
| [CaMeL: Defeating Prompt Injections by Design](camel.md) | 2025 preprint | Capability and control/data separation baseline; RQ1 |
| [AgentPoison](agentpoison.md) | NeurIPS 2024 | Canonical memory/knowledge-base poisoning attack; RQ3 |
| [TMA-NM](tma-nm.md) | 2026 preprint | Origin-bound authority and memory-promotion baseline; RQ1/RQ3 |
| [NeuroTaint / Ghost in the Agent](neurotaint.md) | 2026 preprint | Semantic, causal, and cross-session taint tracking; RQ3/RQ4 |
| [Selection Integrity for LLM Graph Memory](selection-integrity.md) | 2026 preprint | Authenticated-evidence selection channel; RQ2/RQ3 |

## Supporting papers — cite in grouped discussion (8)

| Paper | Year / status | Citation purpose |
|---|---|---|
| [FIDES: Securing AI Agents with Information-Flow Control](fides.md) | 2025 preprint | IFC, taint tracking, planner expressiveness |
| [When Collaboration Fails](when-collaboration-fails.md) | Scientific Reports 2026 | Persuasion-driven adversarial influence in debate |
| [Selected Evidence, Omitted Information, and Belief Updating](selected-evidence.md) | SSRN 2026 preprint | Evidence selection, omission, and WYSIATI |
| [Lost in the Middle](lost-in-the-middle.md) | TACL 2024 | Position-dependent evidence use |
| [InjecAgent](injecagent.md) | ACL Findings 2024 | Indirect prompt-injection benchmark |
| [Task Shield](task-shield.md) | ACL 2025 | Task-alignment defense and utility baseline |
| [MINJA](minja.md) | 2025/2026 preprint | Query-only memory injection |
| [MemLineage](memlineage.md) | 2026 preprint | Memory provenance and derivation-lineage enforcement |

## Conditional papers — include when the scope requires them (2)

| Paper | Include when… |
|---|---|
| [FlowSteer](flowsteer.md) | workflow position, planner steering, or MAS topology enters the experiment |
| [Prompt Infection](prompt-infection.md) | the bio/virus framing or replication across agents remains in the paper |

## Reading map by research question

- **RQ1 — Authority Boundary:** CaMeL, FIDES, InjecAgent, Task Shield, TMA-NM.
- **RQ2 — Receptor Boundary:** Lying with Truths, When Collaboration Fails, Lost in the Middle, Selection Integrity, and optionally FlowSteer.
- **RQ3 — Memory Promotion Boundary:** AgentPoison, MINJA, MemLineage, TMA-NM, NeuroTaint, Selection Integrity.
- **RQ4 — Authority–Semantic Relationship:** the unresolved boundary between CaMeL/TMA-NM-style action guarantees and Lying with Truths/NeuroTaint-style semantic influence.

## Curation status

- Verification state: **verified from primary publisher or arXiv pages**.
- Last checked: **2026-08-27**.
- Lifecycle: **active watchlist**. Recent preprints should be rechecked for revisions or venue publication before submission.
- CoPHEME, AgentDojo, TaintBench, ContractNLI, and similar datasets are benchmark references and are not counted among the 16 method papers above.

[Back to repository home](../README.md)
