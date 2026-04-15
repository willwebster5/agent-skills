# agent-skills

A Claude Code plugin marketplace — a collection of CrowdStrike security skills and plugins.

## Installation

Add this marketplace to your Claude Code setup:

```
/plugin marketplace add willwebster5/agent-skills
```

Then browse and install available plugins:

```
/plugin search
```

## Available Plugins

| Plugin | Description | Maturity |
|--------|-------------|----------|
| `crowdstrike-soc` | Unified SOC analyst workflow — triage, investigate, hunt, tune, manage cases | Beta |
| `crowdstrike-soc-agents` | Agent-delegated SOC workflow with specialized sub-agents | Experimental |
| `crowdstrike-logscale-security-queries` | CQL query development, optimization, and troubleshooting | Stable |
| `crowdstrike-cql-patterns` | Curated CQL pattern catalog — correlation, enrichment, aggregation, scoring | Stable |
| `crowdstrike-behavioral-detections` | Multi-event behavioral rules using correlate() — attack chain patterns | Stable |
| `crowdstrike-detection-tuning` | NGSIEM detection tuning with 38 enrichment functions | Stable |
| `crowdstrike-fusion-workflows` | Falcon Fusion SOAR workflow authoring and deployment | Stable |
| `crowdstrike-threat-hunting` | Autonomous PEAK-framework threat hunting | Stable |
| `crowdstrike-source-threat-modeling` | Threat-model-first detection planning for new data sources | Stable |
| `crowdstrike-response-playbooks` | Detection-to-response mapping and SOAR playbook design | Experimental |

**Maturity levels:**
- **Stable** (v1.0.0) — Complete methodology, tested in production workflows
- **Beta** (v0.1.0) — Functional and actively used, still evolving
- **Experimental** (v0.1.0) — Early stage or architectural prototype

## License

MIT
