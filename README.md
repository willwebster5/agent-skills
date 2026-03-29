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

### SOC Operations

| Plugin | Description |
|--------|-------------|
| `crowdstrike-soc` | Unified SOC analyst workflow — triage alerts, investigate, hunt threats, tune detections, manage cases |
| `crowdstrike-soc-agents` | Agent-delegated SOC workflow — distributes triage and investigation across specialized sub-agents |

### Detection Engineering

| Plugin | Description |
|--------|-------------|
| `crowdstrike-logscale-security-queries` | Develop and troubleshoot CQL security detection queries for LogScale |
| `crowdstrike-detection-tuning` | Tune NGSIEM detections for false positive reduction with 38 enrichment functions |
| `crowdstrike-behavioral-detections` | Design multi-event behavioral detection rules using `correlate()` |
| `crowdstrike-cql-patterns` | Curated CQL detection engineering pattern catalog for NG-SIEM |

### Automation

| Plugin | Description |
|--------|-------------|
| `crowdstrike-fusion-workflows` | Build Falcon Fusion SOAR workflows — discover actions, author YAML, validate |

## License

MIT
