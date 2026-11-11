# MCP incident notes: tool poisoning, rug pulls and shadowing

Source: L. Beurer-Kellner and M. Fischer, "MCP Security Notification: Tool Poisoning
Attacks", Invariant Labs, 1 April 2025. https://invariantlabs.ai/blog/mcp-security-notification
These are summary notes written in our own words for the project's knowledge base,
not a copy of the article.

## ASI01 Tool poisoning: hidden instructions in a tool description
ASI01 Agent Goal Hijack, also LLM01 Prompt Injection (indirect). In a tool poisoning
attack, an MCP server hides instructions inside a tool's description. The model reads
the full description, but the user usually sees only the tool name or a short summary.
The authors argue that MCP clients wrongly treat tool descriptions as trustworthy and
often do not show or sanitise them, so a description becomes a channel for indirect
prompt injection.

## ASI02 Example payload: a poisoned add tool that leaks secrets
ASI02 Tool Misuse and Exploitation, also LLM02 Sensitive Information Disclosure. The
authors' example is a tool called add that claims to add two numbers. Its description
hides a block telling the model to read the user's MCP client configuration file
(~/.cursor/mcp.json, which can hold credentials for other servers) and the user's SSH
private key, then pass their contents in an extra parameter named sidenote. The model
is also told to explain the arithmetic normally and not to mention the file reads.

## ASI02 Why the user did not notice
ASI02 Tool Misuse and Exploitation. In the authors' test with the Cursor client, the
agent followed the hidden instructions. The approval dialog showed only a summarised
tool call, so the user could not see that the arguments contained the SSH key. The
authors add that a model can also be told to encode the stolen data to avoid detection.

## ASI04 Rug pulls: a tool changes after it was approved
ASI04 Agentic Supply Chain Vulnerabilities. A server can be clean when the user first
approves it and later change a tool's description to add malicious instructions. Users
who trusted the first version stay exposed, because the change happens after approval.
The authors compare this to malicious updates of packages on PyPI.

## ASI01 Shadowing: one server changes how another server's tools are used
ASI01 Agent Goal Hijack and ASI02 Tool Misuse and Exploitation. A malicious server can
put instructions in its own tool description that change how the agent uses tools from
a different, trusted server. In the authors' experiment, a fake add tool made the agent
send every email from a trusted send_email tool to an attacker's address, even when the
user named another recipient, and the visible log did not show the change. This lets
credentials from one server be passed to another, and it works even if the user only
calls trusted servers. Combined with a rug pull, it can compromise an agent while
leaving little visible trace.

## Mitigations recommended by the authors (ASI01, ASI02, ASI04)
1. Clear interfaces: show users the full tool description, and clearly separate text
   meant for the user from instructions the model will read.
2. Pinning: pin the versions of servers and tools and verify a hash or checksum before
   use, so any change to a tool is detected.
3. Cross-server protection: enforce strict boundaries and data-flow controls between
   MCP servers.
The authors also stress that security must cover the data passed to and from the
model, not only tool descriptions, and advise caution with third-party servers that
share a context with sensitive data or credentials.
