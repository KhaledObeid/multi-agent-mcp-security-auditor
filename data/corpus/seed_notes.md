# AgentGuard seed notes (team-written starter, replace with primary sources)

## ASI01 Agent Goal Hijack
An attacker redirects an agent's objective through content the agent reads rather than code it runs. In MCP this usually appears as tool poisoning: a tool description contains instructions aimed at the model, often hidden in tags such as <IMPORTANT>, in HTML comments, or after long whitespace. Typical payloads ask the model to read secrets, call another tool first, or hide the behaviour from the user. Mitigations: treat tool descriptions as untrusted input, show full descriptions to users at approval time, strip or flag imperative language aimed at the model, and require confirmation for sensitive actions.

## ASI02 Tool Misuse and Exploitation
The agent uses a legitimate tool in an unsafe or unintended way, for example passing secret file contents in a hidden parameter, or sending data to a URL taken from a description. Mitigations: least-privilege tool design, argument validation, allow-listed network destinations, and logging every tool call with its arguments.

## ASI03 Identity and Privilege Abuse
A tool requests broader scopes or credentials than its function requires, such as wildcard file-system access for a text formatter, or reuses the user's identity for unrelated actions. Mitigations: grant the narrowest scope, compare requested permissions with the stated purpose, and use short-lived scoped tokens.

## ASI04 Agentic Supply Chain Vulnerabilities
Risks inherited from third-party tools, MCP servers, plugins and their dependencies. Includes known CVEs in dependencies and the rug pull pattern, where a tool is approved in a safe version and later updated with malicious behaviour. Mitigations: pin versions and hashes of tool definitions, re-review on every change, and scan dependencies against vulnerability databases such as OSV.

## ASI05 Unexpected Code Execution
The agent or a tool can execute shell commands or arbitrary code, for example through subprocess calls, eval, or shell=True. Mitigations: sandbox execution, remove shell access when it is not needed, and require human approval for commands.

## ASI06 Memory and Context Poisoning
Malicious content is written into an agent's memory or retrieved context and influences later decisions. Mitigations: validate what is stored, separate trusted and untrusted context, and expire or review long-term memory.

## LLM01 Prompt Injection
Inputs that change the model's behaviour in unintended ways. Indirect prompt injection arrives through data the model processes, such as documents, web pages and tool descriptions. Invisible Unicode characters (zero-width spaces, Unicode tag characters) can hide injected text from human reviewers while the model still reads it. Mitigations: normalise and strip invisible characters, delimit untrusted content, and never let retrieved content grant new permissions.

## LLM06 Excessive Agency
An LLM-based system is given more functionality, permissions or autonomy than it needs, so a single injection can cause real damage. Mitigations: minimise tools and permissions, require approval for high-impact actions, and log actions for audit.
