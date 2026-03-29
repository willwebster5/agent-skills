# agent-skills

A Claude Code plugin marketplace — a collection of skills and plugins for Claude Code.

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

*No plugins yet — check back soon.*

## Adding a Plugin

Each plugin lives in its own directory under `plugins/`:

```
plugins/
└── my-plugin/
    ├── .claude-plugin/
    │   └── plugin.json
    └── skills/
        └── my-skill/
            └── SKILL.md
```

### Plugin manifest (`plugin.json`)

```json
{
  "name": "my-plugin",
  "description": "What this plugin does",
  "version": "0.1.0"
}
```

### Skill file (`SKILL.md`)

```markdown
---
name: my-skill
description: When and how to use this skill
---

Skill instructions go here.
```

## License

MIT
