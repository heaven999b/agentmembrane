# Data

This repo does **not** redistribute any dataset. Evaluation uses **ContractNLI**,
released under **CC BY 4.0**; obtain it yourself and place it under
`data/official/contract-nli/`.

## ContractNLI

- Paper: Koreeda & Manning, *ContractNLI: A Dataset for Document-level Natural
  Language Inference for Contracts*, Findings of EMNLP 2021.
- Source: https://github.com/stanfordnlp/contract-nli
- License: Creative Commons Attribution 4.0 International (CC BY 4.0).
- Dataset owner: Hitachi America, Ltd. (see the dataset's own `TERMS`).

Expected local layout (git-ignored):

```
data/official/contract-nli/{train,dev,test}.json
vendor/contract-nli/resources/contract-nli.zip
```

## Building the frozen manifest

The experimental subset is deterministic given the selection seed `20260824`, so it is
regenerated rather than committed (the manifest embeds contract-clause text):

```bash
python3 -m agentmembrane.contractnli   # or the build-manifest entry point:
python3 -m agentmembrane.real_asr_v3 build-manifest \
  --parent data/manifests/contractnli_dev_semantic_risk_n150_seed20260824.json \
  --output data/manifests/contractnli_dev_semantic_risk_n150_v3_seed20260824.json
```

The n=150 subset covers 57 unique contracts, balanced 75 Entailment / 75 Contradiction,
each with all gold evidence retained inside a fixed 12-span candidate packet.
