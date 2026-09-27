# AgentShield Lab

**An explainable, zero-cost prompt-injection firewall for AI agent workflows.**

AgentShield scans emails, retrieved documents, webpages, and tool output before that untrusted text reaches an AI agent with access to tools or private context. It runs entirely in the browser: no API key, backend, account, or telemetry.

## Why this project

As AI systems move from chat to action, indirect prompt injection becomes a practical engineering problem: ordinary content can contain instructions that attempt to override an agent, extract secrets, or trigger tools. AgentShield makes those risks visible and gives developers a small, inspectable policy engine they can extend.

## Highlights

- **Explainable scoring** — every risk score maps to visible signals and evidence
- **Six attack families** — override, exfiltration, tool abuse, role hijacking, concealment, and obfuscation
- **Actionable output** — generates a least-privilege handling plan for the agent
- **Private by design** — all analysis stays in the browser
- **Zero operating cost** — static files, no model endpoint, no database
- **Dependency-free core** — the scanner is plain JavaScript and easy to embed

## Run locally

Open `dist/index.html` from a local web server. For example:

```bash
npx serve .
```

Then open the printed URL and choose `dist/`.

## Test

```bash
npm test
```

## Architecture

```text
Untrusted content
      │
      ▼
Normalization + pattern features
      │
      ▼
Transparent weighted risk model
      │
      ├── Evidence highlights
      ├── Signal confidence
      └── Agent handling policy
```

The current engine is intentionally small and auditable. Good next contributions include multilingual rules, benchmark fixtures, WASM model adapters, and framework middleware.

## Important limitation

AgentShield is a defensive signal layer, not a proof of safety. Use it with instruction/data separation, least-privilege tools, output validation, and human approval for consequential actions.

## License

MIT

