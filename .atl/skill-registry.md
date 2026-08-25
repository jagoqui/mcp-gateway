# Skill Registry — mcp-gateway

Built by `sdd-init` on 2026-08-25. Scanned user-level skill directories
(`~/.agents/skills`, `~/.config/opencode/skills`, `~/.claude/skills` — identical
sets, deduplicated by name). No project-level skill directories exist yet
(fresh project). `sdd-*`, `_shared`, and `skill-registry` skills are excluded
per scan rules — SDD phase skills are loaded by the orchestrator directly.

No project convention files found (`agents.md`, `AGENTS.md`, `CLAUDE.md`,
`.cursorrules`, `GEMINI.md`, `copilot-instructions.md`) — directory has no
files yet beyond empty `services/auth-gateway` and `services/engram-monitor`
placeholders.

## Skills Index

| Skill | Trigger | Path | Scope |
|---|---|---|---|
| branch-pr | Creating, opening, or preparing PRs for review | `~/.claude/skills/branch-pr/SKILL.md` | user |
| chained-pr | PRs over 400 lines, stacked PRs, review slices | `~/.claude/skills/chained-pr/SKILL.md` | user |
| cognitive-doc-design | Writing guides, READMEs, RFCs, onboarding, architecture, review-facing docs | `~/.claude/skills/cognitive-doc-design/SKILL.md` | user |
| comment-writer | PR feedback, issue replies, reviews, Slack messages, GitHub comments | `~/.claude/skills/comment-writer/SKILL.md` | user |
| gentle-ai-bench | bench, journey(s), driven mode, gentle-ai-bench, journey corpus, j-numbers, bench axis | `~/.claude/skills/gentle-ai-bench/SKILL.md` | user |
| go-testing | Go tests, go test coverage, Bubbletea teatest, golden files | `~/.claude/skills/go-testing/SKILL.md` | user |
| issue-creation | Issue creation, bug reports, feature requests, issue approval | `~/.claude/skills/issue-creation/SKILL.md` | user |
| judgment-day | judgment day, dual review, adversarial review, juzgar | `~/.claude/skills/judgment-day/SKILL.md` | user |
| rdd-defect-workflow | RDD, receipt-driven development, review authority, receipt/lineage, correction/recovery, delivery gate/kill switch, bounded review defects | `~/.claude/skills/rdd-defect-workflow/SKILL.md` | user |
| skill-creator | New skills, agent instructions, documenting AI usage patterns | `~/.claude/skills/skill-creator/SKILL.md` | user |
| skill-improver | Improve skills, audit skills, refactor skills, skill quality | `~/.claude/skills/skill-improver/SKILL.md` | user |
| systemic-issue-triage | New issue, bug report, triage, backlog, issue flood, community report, root cause, dead-end, blocked user | `~/.claude/skills/systemic-issue-triage/SKILL.md` | user |
| work-unit-commits | Implementation, commit splitting, chained PRs, keeping tests and docs with code | `~/.claude/skills/work-unit-commits/SKILL.md` | user |

## Notes

- `go-testing` is not relevant to this project's stack (Node/Express, not Go);
  kept in the index per scan rules (index everything found), phases should
  prefer Node/JS-specific patterns once introduced.
- `rdd-defect-workflow` and RDD in general are relevant once `git init` runs
  and the user enables `gentle-ai review mode` — not actionable yet.
- Re-scan after `git init` and after `services/auth-gateway` gains real files,
  since project-level skill dirs and convention files may appear then.
