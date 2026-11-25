# ECC rules

Rule packs copied from [ECC](https://github.com/affaan-m/ECC) release v2.2.3
(MIT, see `LICENSE` in this folder). Claude Code plugins cannot ship rules, so
they are vendored here; the ECC plugin itself (agents, skills, commands, hooks)
is enabled for this project in `.claude/settings.json`.

- `common/` applies to all files.
- `python/` applies to `*.py` (the generator and `scripts/` tooling).

Repo-specific guidance in `AGENTS.md` / `CLAUDE.md` wins over these generic
rules (for example XML conventions and the API-break checks).

To update: copy the same folders from a newer ECC release and bump the `ref`
in `.claude/settings.json` to match.
