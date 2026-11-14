# RAG corpus sources (Member C)

Put downloaded files (PDF, .md or .txt) directly in this folder, then run `python -m mcp_security_auditor.rag.ingest`.
The team-written starter `seed_notes.md` was removed on 12 November 2026 because its wording matched our own test queries and outranked the primary sources below. Cite every source below in the report's attribution section.n.

| Source | Where to get it | Use it for |
|---|---|---|
| OWASP Top 10 for Agentic Applications 2026 (Dec 2025) | genai.owasp.org, Agentic Security Initiative resources | ASI01 to ASI10 definitions, attack scenarios, mitigations |
| OWASP Top 10 for LLM Applications | genai.owasp.org | LLM01 prompt injection, LLM06 excessive agency, supply chain |
| OWASP MCP Top 10 | owasp.org project page | MCP-specific risks (tool poisoning, shadowing) |
| MCP specification, security best practices page | modelcontextprotocol.io | official guidance on consent, scopes, token handling |
| Public incident write-ups on MCP tool poisoning and rug pulls | security vendor blogs (search "MCP tool poisoning attack") | concrete examples for the Threat Analyst and for new samples |

Licensing note: OWASP material is published under Creative Commons; keep the attribution. For blog posts, store your own summary notes rather than copying full articles.
