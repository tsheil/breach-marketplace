## Skill Development
The core breach skills are designed to be used together in a cohesive framework and also as standalone skills.
Make sure the core breach skills do not conflict with each other.

### Core Development Skills
Use and reference these to ensure best practices.
- skill-creator
- plugin dev

### When modifying skills:

1. Update `plugins/breach/README.md` (plugin README)
2. Update `README.md` (marketplace README)
3. Update `plugins/breach/.claude-plugin/plugin.json` (description + version bump)
4. Update `.claude-plugin/marketplace.json` (description + version bump)

**Version bumps are required for auto-update.** Always bump at least the patch version (e.g., 1.4.0 → 1.4.1) in both `plugin.json` and `marketplace.json` on every change. Without a version bump, Claude Code instances with the plugin installed will not pick up the update.

**Before committing:** Verify both READMEs are up to date with current skill names, descriptions, and pipeline diagrams. The READMEs are the primary documentation for users — stale READMEs cause confusion.

### Skill naming convention

All breach skill SKILL.md frontmatter must include a `name` field using the format `breach-{skill-name}`:
- `breach-code-recon`
- `breach-hunt`
- `breach-static-scan`
- `breach-code-analysis`
- `breach-findings`
- `breach-validate-finding`
- `breach-chain-analysis`
- `breach-custom-rules`
- `breach-report`


## Reference Projects and Research
The following projects are focused on using AI for vulnerability discovery and should be referenced for ideas and inspiration.

### Claude Code Plugin Marketplaces
https://github.com/trailofbits/skills - A Claude Code plugin marketplace from Trail of Bits providing skills to enhance AI-assisted security analysis, testing, and development workflows.
https://github.com/trailofbits/skills-curated - Trail of Bits' reviewed and approved Claude Code plugins. Every skill and marketplace here has been vetted for quality and safety.
https://github.com/ghostsecurity/skills - Plugin marketplace repository for Ghost Security's AI-native application security skills for Claude Code.

### AI-Powered Security Research Frameworks
https://github.com/gadievron/raptor - RAPTOR is an autonomous offensive/defensive security research framework, based on Claude Code. It empowers security research with agentic workflows and automation.
https://github.com/KeygraphHQ/shannon - Shannon is an AI pentester that delivers actual exploits, not just alerts.

### ARXIV
https://www.arxiv.org/abs/2602.07666 - SoK: DARPA's AI Cyber Challenge (AIxCC): Competition Design, Architectures, and Lessons Learned