# Sigma Research Workspace

This repository is a research-first workspace that ties adversary technique studies to Sigma detections.  
Folders contain notes, diagrams, and draft rules that document how behaviors were tested and how they might be detected.

## Purpose

- Capture technique research end-to-end, from lab observations to Sigma-ready logic.
- Keep an auditable trail that explains why a detection exists before it reaches production tooling.
- Provide a sandbox for experimentation so ideas can mature before they are operationalized.

## TTP Prioritization

Detection research and TTP coverage decisions here are intentionally driven by:

- **ATT&CK heat maps** - focus on tactics/sub-techniques frequently abused in real campaigns.
- **Visibility models** - align work with telemetry that is already available (EDR/Sysmon/Security logs).
- **Attack paths** - explore techniques that meaningfully advance an adversary along common kill chains.

You should re-score and re-rank these items against your own heat maps, logging coverage, and risk models before adopting anything beyond research.

## Usage Guidance

1. Review the technique notes to understand assumptions, required logging, and known limitations.
2. Adapt Sigma rules to your telemetry reality (field names, parsers, enrichments) before promotion.
3. Validate each rule in a lab or purple-team exercise to make sure it behaves as expected with your data.

## Research Disclaimer

All content is published for research purposes. Behaviors, logging paths, and false-positive guidance reflect the author's environment at the time of testing.  
Be careful when reusing any rule or workflow: always cross-check against your visibility, detection engineering standards, and ATT&CK prioritization models.
