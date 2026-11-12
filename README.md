# Key Redactor

Static Astro app. Redact likely secrets from configuration before sharing with AI. All file reading and redaction happen in the browser; no backend, uploads, storage, analytics, external fonts or AI calls.

## Run

Node.js 22.12+ (Node.js 24 recommended).

```sh
npm ci --ignore-scripts
npm run dev
```

Open the local URL printed by Astro. For production behavior and CSP:

```sh
npm test
npm run build
npm run preview
```

Deploy `dist/` to a static host if desired. Deployment is not part of this task. Serve over HTTPS for clipboard support. CSP blocks connections in production; development uses Astro/Vite's local development connection. Astro CLI telemetry is disabled in npm scripts.

## Behavior

Paste text or open/drop a UTF-8 file. Choose Auto-detect, JSON/JSONC, .env or Plain text. Copy or download the redacted preview; original files are never modified. Clear removes visible input/output, not clipboard contents or guaranteed in-memory copies.

Sensitive key names, common provider tokens, bearer/JWT tokens, PEM private keys, connection-string passwords and URL passwords are detected. Repeated identical detected source values share a placeholder within each scan. JSONC comments, trailing commas, whitespace and ordinary values stay unchanged outside redaction spans. Numeric/boolean secret values become placeholder strings. Escaped JSON credentials may require replacing an entire string to avoid invalid escapes.

Detection is best-effort. Review every output before sharing. Public keys, endpoints, feature flags and ordinary settings are retained. Unknown credentials, unusual formats, token metadata and credential references may be missed. Plain text support is pattern-based, not a universal parser; select the proper format when auto-detection guesses wrong. No entropy guessing or external secret validation.

Limits: 500,000 UTF-16 code units, 1 MiB per file, 100 JSON nesting levels. Binary/NUL and invalid UTF-8 files are rejected. Malformed JSON/JSONC and unterminated quoted assignments block export; existing input remains available for correction. Content is rendered as text, never HTML.

Browser extensions, clipboard managers, OS memory/swap and compromised hosting are outside this app's privacy boundary. No claim of secure erasure or complete secret removal. Use a trusted local checkout for highly sensitive material.

Specification and delivery evidence: `docs/specs/browser-redactor/spec.md`.
