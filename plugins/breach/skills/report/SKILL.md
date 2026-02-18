---
description: "Generate a professional security vulnerability report with CVSS scoring and bounty-ready presentation. This skill should be used when the user wants to write a security report, format vulnerability findings, create a bounty submission, calculate CVSS scores, prepare a report for HackerOne or Bugcrowd, turn raw vulnerability notes into a structured security assessment, or generate reports from verified findings in the finding lifecycle. This is the final phase of the breach pipeline. Enforces a hard gate on human-verified findings in lifecycle mode."
---

# Report Generation Skill

This skill transforms validated security findings into professional, bounty-ready vulnerability reports. The output is a structured markdown document with CVSS scoring, actionable reproduction steps, and persuasive impact narratives designed to maximize triager engagement and bounty payouts.

Every report produced by this skill follows a proven methodology refined across thousands of successful submissions. The goal is not just documentation — it is communication. A vulnerability report is a persuasive document that must convince a triager, a security engineer, and often a product manager that the finding is real, impactful, and worth fixing immediately.

## Section 1: Report Generation Procedure

For each validated finding from the validate phase, apply the following procedure in order. Do not skip steps. Each step builds on the previous one, and the final report quality depends on the rigor applied at every stage.

**Step 1 — Apply the Finding Template.** Load the full finding template from `report-template.md` in the references directory. Every finding must conform to this template without exception. The template exists to enforce consistency and completeness. A finding without a filled template is an incomplete finding, regardless of its severity.

**Step 2 — Calculate the CVSS Score.** Using the reference material in `cvss-scoring.md`, walk through each of the eight base metrics for the finding. Do not guess or approximate. For each metric, select the value that reflects the realistic worst-case scenario for the vulnerability. Document the full CVSS vector string and the resulting numeric score. If the score feels wrong — too high or too low — revisit each metric and verify the selection. The CVSS score is the single most scrutinized element of any bounty report, and an inaccurate score undermines the entire submission.

**Step 3 — Write the Impact Narrative.** This is where most reports fail. Technical descriptions of what the code does wrong are insufficient. The impact narrative must answer three questions in business terms: What data is exposed or at risk? What operations or business processes are compromised? What is the blast radius — how many users, systems, or records are affected? Write in concrete terms. "An attacker can read all user payment information" is effective. "The endpoint lacks proper authorization checks" is not. The impact narrative is the first thing a triager reads after the title, and it determines whether they take the finding seriously or skim the rest.

**Step 4 — Craft Reproduction Steps.** Apply the triager test: can someone who has never seen the application reproduce this finding in under five minutes using only the steps provided? Every URL must be complete. Every payload must be exact. Every header must be specified. Every expected response must be documented. If a step requires setup (creating a user account, uploading a file, navigating to a specific state), that setup must be explicitly included. Do not assume the reader has any context about the application. Number each step sequentially and include the expected outcome at each stage.

**Step 5 — Provide the Proof of Concept.** The PoC must be copy-paste-ready. If it is a script, it must run without modification on a standard system with common tools installed. If it is a series of curl commands, each command must be complete with all headers, cookies, and payloads. If the PoC requires dependencies, list them with exact installation commands. Include comments in the code explaining what each section does. A PoC that requires debugging is a PoC that gets the report deprioritized.

**Step 6 — Write Remediation Guidance.** Provide a specific, implementable fix. Show the exact code change — before and after. If there are multiple valid remediation approaches, list them in order of preference with trade-offs for each. Reference relevant security libraries or framework features that address the vulnerability class. The remediation section serves two purposes: it demonstrates expertise (which builds trust with the security team) and it accelerates the fix (which gets the report resolved faster, which gets the bounty paid faster).

## Lifecycle Gate: Human Verification Required

Before generating a report, check whether a `findings/` directory exists in the current working directory or any parent directory (up to 5 levels). The `findings/` directory is recognized by having stage subdirectories (`potential/`, `confirmed/`, `validated/`, `verified/`, `reported/`, `rejected/`).

### If `findings/` directory is found: Lifecycle Mode

**Hard gate: only process findings from `findings/verified/`.**

This gate cannot be overridden. The report skill will not generate reports for findings that have not been human-verified.

1. **Check `findings/verified/`** for finding folders. If verified findings exist, proceed with report generation using the finding.md contents from each verified finding folder.
2. **If no verified findings exist**: Do not generate a report. Instead, report the count of findings in each stage and instruct the user:

   > **No verified findings available for reporting.**
   >
   > Current finding counts:
   > - potential: [N]
   > - confirmed: [N]
   > - validated: [N]
   > - verified: 0
   > - reported: [N]
   > - rejected: [N]
   >
   > To generate a report, move validated findings to `findings/verified/`:
   > 1. Review each finding in `findings/validated/`
   > 2. Move approved finding folders to `findings/verified/`
   > 3. Update `stage` to "verified" in each finding.md frontmatter
   > 4. Re-run `/breach:report`

   Stop execution. Do not generate a partial report or fall back to conversation findings.

3. **Post-report**: For each finding included in the report, update its `finding.md` frontmatter (`stage` to "reported", `last_moved` to current ISO 8601 timestamp) and move the finding folder from `findings/verified/` to `findings/reported/`.

### If no `findings/` directory is found: Standalone Mode

No gate applies. Accept findings from conversation context and generate the report as normal. This preserves backward compatibility when the finding lifecycle is not in use.

## Section 2: Severity and CVSS Scoring

Reference `cvss-scoring.md` for the complete metric definitions, numeric values, and common vulnerability score benchmarks. For each finding, the scoring process is as follows:

1. **Calculate the CVSS v3.1 Base Score.** Walk through each metric methodically. Attack Vector (AV) — can this be exploited over the network, or does it require local access? Attack Complexity (AC) — are there conditions beyond the attacker's control that must exist? Privileges Required (PR) — does the attacker need an account, and if so, what level? User Interaction (UI) — does a victim need to perform an action? Scope (S) — does the vulnerability impact resources beyond its security scope? Then assess the impact triad: Confidentiality (C), Integrity (I), and Availability (A). For each, determine whether the impact is None, Low, or High.

2. **Provide the full CVSS vector string.** Format it exactly as specified: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`. This string must be pasteable directly into any CVSS calculator for verification. An incorrect vector string is an immediate credibility hit.

3. **Map the numeric score to severity.** Critical: 9.0-10.0. High: 7.0-8.9. Medium: 4.0-6.9. Low: 0.1-3.9. Use these ranges without deviation. Some programs have their own severity mappings — note any program-specific adjustments separately.

4. **Write a severity justification.** Explain in business terms why the assigned severity is appropriate. This is not a restatement of the CVSS metrics. It is a narrative that connects the technical characteristics of the vulnerability to real-world consequences. "This is rated Critical because an unauthenticated attacker can extract the entire user database remotely without any user interaction, affecting all platform users."

5. **Note environmental factors.** Document any environmental considerations that could adjust the score in either direction. Compensating controls, deployment context, data sensitivity, and user population size are all relevant. Be honest about factors that might lower the effective severity — this builds credibility.

## Section 3: Report Structure

The final report follows a fixed structure. Do not deviate from this ordering. Each section serves a specific purpose for a specific audience, and the ordering reflects how reports are actually consumed by security teams.

### 1. Executive Summary

Two to three paragraphs maximum. This section is for engineering leadership and product managers who will not read the full report. Include: total number of findings broken down by severity, identification of the most critical findings with one-sentence descriptions, an overall assessment of the application's security posture, and a prioritized list of recommended immediate actions. Write this section last, after all findings are documented, so it accurately reflects the complete picture.

### 2. Findings Summary Table

A sortable markdown table with the following columns: ID (sequential, prefixed by severity letter — C for Critical, H for High, M for Medium, L for Low), Title (concise but descriptive), Severity (word and color if supported), CVSS Score (numeric with one decimal), CWE (number and short name), Component (affected file or endpoint), and Status (New, Confirmed, Triaged). This table serves as the navigation index for the entire report.

### 3. Individual Findings

Each finding receives the full template treatment from `report-template.md`. Order findings by severity, with Critical findings first and Low findings last. Within the same severity level, order by CVSS score descending. Each finding must be entirely self-contained — a reader should be able to understand, reproduce, and remediate the finding without referencing any other section of the report.

### 4. Vulnerability Chain Analysis

Document any vulnerability chains discovered during analysis. A chain exists when two or more lower-severity findings can be combined to create a higher-impact attack. For each chain: describe the individual components, explain how they connect, demonstrate the combined attack path, and calculate the effective severity of the chain (which should be higher than any individual component). Include a textual flow diagram showing the chain progression. Chains are where experienced researchers differentiate themselves from automated scanners.

### 5. Remediation Priority List

Order all findings by a composite score derived from three factors: (1) severity — higher severity fixes first, (2) ease of exploitation — easier-to-exploit vulnerabilities get priority, (3) ease of fix — simpler fixes get priority when severity and exploitability are equal. Group "quick wins" at the top of the list: these are findings with high impact that can be fixed with minimal effort, such as adding an authorization check or enabling a security header. Include estimated effort levels (trivial, moderate, significant, major) for each remediation.

### 6. Methodology

A brief section documenting the approach taken during the review. Include: the methodology framework used (OWASP Testing Guide, code review, dynamic analysis, or a combination), the scope of the review (what was examined and what was not), any tools used during analysis, the time period of the review, and explicit limitations or out-of-scope areas. This section protects both the researcher and the organization by setting clear expectations about coverage.

## Section 4: Bounty Optimization

Reference `bounty-wisdom.md` for the complete tactical playbook. The following principles are embedded directly in every report this skill produces:

**Lead with impact, not bug class.** The title and first sentence of every finding must communicate what an attacker can do, not what the vulnerability is. "Unauthenticated attacker can read all user emails" wins. "IDOR in /api/messages endpoint" loses. Triagers process dozens of reports daily. The ones that communicate immediate business risk get attention.

**First paragraph determines priority.** Triagers read the first paragraph and skim everything else on first pass. The worst-case scenario in business terms must appear in the first three sentences. If the triager has to read the full report to understand why this matters, the report will sit in the queue.

**Reproduction steps must be copy-paste.** Apply the triager test rigorously: can someone who has never seen the application reproduce this finding in under five minutes? If the answer is no, rewrite the steps. Include exact URLs, exact payloads, exact headers, and exact expected responses. Ambiguity in reproduction steps is the primary cause of "not reproducible" closures.

**Preempt objections.** Anticipate the reasons the security team might dismiss the finding and address them proactively in the report. If the application has a WAF, demonstrate that the payload bypasses it or explain that the vulnerability exists at the code level regardless of WAF presence. If the feature might be considered "by design," explain why the design creates a security risk that differs from the intended behavior. If rate limiting exists, demonstrate that it does not prevent exploitation.

**Include remediation.** Always provide a specific, implementable fix. This serves three purposes: it demonstrates deep understanding of the vulnerability, it builds trust with the security team, and it accelerates resolution. Faster resolution means faster bounty payment.

**Submit chains as single reports.** When findings combine into an attack chain, submit the chain as one comprehensive report. Reference the individual components within the chain report. Do not submit individual chain components as separate reports — they will be closed as low severity, and reassembling them later into a chain is an uphill battle.

## Section 5: Output

The final deliverable is a complete markdown report with the following characteristics:

- A table of contents with functioning anchor links to every section and every individual finding
- Consistent formatting throughout — heading levels, bullet styles, code block formatting, and emphasis patterns must be uniform
- All code blocks annotated with the correct language identifier for syntax highlighting
- CVSS vector strings formatted for direct paste into online calculators
- All proof-of-concept code in fenced code blocks with explicit setup instructions, dependencies, and execution commands
- Clean, professional tone throughout — factual, precise, and respectful
- No informal language, no humor, no editorializing beyond the impact narrative

The report should be immediately submittable to any bug bounty platform (HackerOne, Bugcrowd, Intigriti) or deliverable as a professional security assessment to a client.

## Fallback

If this skill is invoked without validated findings from a previous phase, do not fail silently. Prompt the user to describe their findings in whatever format they have available — notes, code snippets, screenshots, or verbal descriptions. Apply the full template structure to whatever information is provided, marking any gaps that need to be filled before submission. A partially structured report is always better than an unstructured one.

## Pipeline

Report generation is the final phase of the breach workflow.

- **Lifecycle mode**: Reported findings have been moved to `findings/reported/`. The security report covers all human-verified findings. For additional targets or a new discovery cycle, run `/breach:hunt` or `/breach:recon` on a different scope.
- **Standalone mode**: The validated findings have been transformed into a professional, submission-ready document. For additional targets, run `/breach:recon` on a different scope.
