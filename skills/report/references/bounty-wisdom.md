# Bug Bounty Report Writing Wisdom

Practical guidance for writing vulnerability reports that get triaged quickly, scored accurately, and paid at the appropriate tier. These principles are derived from patterns observed across thousands of successful and unsuccessful submissions.

## The First Paragraph Formula

The first paragraph of every finding determines its fate. Triagers process dozens of reports daily and make initial priority decisions based on the opening sentences alone. Structure every first paragraph as follows:

- **Sentence 1**: What an attacker can do. State the impact in business terms, not the technical mechanism. Focus on the action and its consequence.
- **Sentence 2**: What access or conditions are needed. Is this unauthenticated? Does it require a low-privilege account? Is user interaction needed?
- **Sentence 3**: What data or users are affected. Quantify the scope of impact. How many users? What type of data?

**Strong example:**
"An unauthenticated attacker can read any user's private messages by manipulating the message ID parameter. No special conditions or user interaction are required. All users with private messages are affected, potentially exposing sensitive communications for the platform's entire user base."

**Weak example:**
"There is an Insecure Direct Object Reference vulnerability in the messages API. The endpoint does not check whether the authenticated user owns the requested message. This could allow access to other users' messages."

The strong example leads with what an attacker can do. The weak example leads with what the bug is called. The triager cares about the former.

## The Triager Test

Before submitting any report, run it through these checks:

- **Can someone who has never seen the application reproduce this in under five minutes?** If the answer is no, the reproduction steps are incomplete. Add every detail needed: exact URLs with the target domain, exact HTTP methods, exact headers with values, exact payloads, and exact expected responses at each step.
- **Is every URL, parameter, header, and payload explicitly stated?** Do not write "change the ID parameter." Write "Change the `id` parameter value from `1234` to `1235` in the URL: `GET /api/v2/messages/1235`." Do not write "use your session cookie." Write "Include the cookie: `session=abc123def456`."
- **Are screenshots or recordings necessary?** For visual bugs (UI redress, clickjacking, visual content injection), screenshots are essential. For API vulnerabilities, they are optional but helpful. For complex multi-step exploits, a screen recording can prevent "not reproducible" closures.
- **Is the target clearly identified?** State the exact URL, not "the application" or "the API." If testing against a staging environment, note this and confirm the vulnerability exists on production (if in scope).

## Duplicate Avoidance

Duplicates are the most common source of wasted effort in bug bounty. Minimize duplicate risk with these practices:

- **Search disclosed reports first.** Most platforms allow searching for disclosed reports on a program. Read them. Understand what has already been found and at what severity.
- **Check common vulnerability patterns.** If you found a basic XSS or a missing rate limit, assume it has been reported. Look for the non-obvious variant, the deeper impact, or the chain potential before submitting.
- **If reporting a variant, explicitly differentiate.** State clearly: "This is distinct from the previously disclosed XSS in the search parameter (report #12345) because it bypasses the CSP via a different injection point in the user profile field and achieves session hijacking rather than content injection."
- **File quickly for high-severity findings.** The window between discovery and duplicate closure is measured in hours for critical findings on active programs. Same-day submission from discovery is the target for anything High severity or above.

## Common Rejection Reasons and Response Strategies

Understanding why reports get rejected is as important as writing them well. For each common rejection, there is a strategic response:

**"This is by design."** Demonstrate the security impact of the design decision. Show that the intended functionality creates an unintended security consequence. Reference similar findings accepted in other programs. Frame it as "the design achieves its intended purpose, but it also enables an attacker to..." rather than "the design is wrong."

**"We have WAF/rate limiting."** Demonstrate the bypass if one exists. If no bypass exists at the network level, explain that the vulnerability exists in the application code and would be exploitable if the WAF rule were modified, disabled, or bypassed through an encoding the WAF does not handle. The code-level vulnerability is a valid finding regardless of network-level controls.

**"Low impact."** This is an invitation to demonstrate chains. Show how this finding combines with other vulnerabilities to create a higher-impact attack. Alternatively, demonstrate a more impactful exploitation scenario that was not immediately obvious. Show data extraction, privilege escalation, or account takeover rather than just the existence of the vulnerability.

**"Not reproducible."** Provide additional detail. Specify the exact environment: browser version, operating system, network conditions. Offer to provide a screen recording or conduct a live demonstration. Ask whether the triager is testing against the same environment and build version.

**"Out of scope."** Double-check the program scope before responding. If the target is genuinely out of scope, accept the closure. If there is ambiguity in the scope definition, cite the specific scope language and explain your interpretation. Some programs will reconsider if the finding is high-severity and the scope boundary is unclear.

**"Informational."** This means the triager acknowledges the finding but does not consider it exploitable. Add an explicit exploitation path: demonstrate actual data extraction, show a working account takeover, or prove that the information disclosed enables a concrete follow-up attack. Move it from theoretical to demonstrated.

## Persuasive Writing Techniques

Security reports are persuasive documents. The goal is to convince the reader that the finding is real, impactful, and worth fixing.

- **Use concrete examples, not abstract descriptions.** "The attacker retrieves the victim's full name, email address, phone number, and home address" is stronger than "the attacker accesses PII."
- **Quantify impact when possible.** "Affects all 2.3 million registered users" is stronger than "affects all users." If you do not know the exact number, estimate: "Based on the public user count of approximately 2 million..."
- **Compare to real-world breaches with similar root causes.** "This is the same class of vulnerability (IDOR) that led to the 2019 First American Financial breach exposing 885 million records" adds weight without being adversarial.
- **Show you understand the business context.** Reference the application's purpose and user base. A data exposure in a healthcare app has different implications than in a social media app. Demonstrate that awareness.
- **Be respectful and professional.** Adversarial tone gets reports deprioritized or closed. Never imply incompetence. Phrases like "the security team may not be aware that..." work better than "the developers failed to..."
- **Thank the security team.** A brief acknowledgment of their program and responsiveness builds a constructive relationship. Researchers who build good relationships with security teams get faster triage, more generous scoring, and invitations to private programs.

## Timing and Strategy

When and how you submit affects outcomes as much as what you submit.

- **Submit high-severity findings immediately.** Do not hold a Critical or High finding while searching for more vulnerabilities. The duplicate risk increases with every hour. Submit, then continue hunting.
- **Bundle related findings with the same root cause.** If three endpoints all have the same authorization bypass due to a shared middleware flaw, submit one report covering all three. This is one vulnerability with multiple instances, not three separate findings.
- **For chains, submit the chain first.** Write the comprehensive chain report showing the full attack path and combined impact. Reference individual components within the chain. If you submit individual low-severity components first, they get closed as low-impact, and arguing for a chain upgrade later is difficult.
- **Respond to triager questions within 24 hours.** Responsiveness signals professionalism and keeps the report moving through the triage pipeline. Delayed responses lead to stale reports that get deprioritized.
- **Do not argue severity publicly.** If you disagree with a severity assessment, present your case factually in the report comments with additional evidence. Do not escalate to social media or public channels — this burns bridges and can result in program bans.
