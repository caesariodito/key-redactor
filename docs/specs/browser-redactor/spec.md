# Browser secret redactor

## Intent and authority

Build a static Astro application for pasting configuration into AI tools without deliberately sharing credentials. User chose secret-only redaction, preserving useful settings and structure, and approved implementation, Git initialization, Astro installation, local task branch/worktree and one independent Herdr reviewer with at most two fix/recheck rounds. No deployment, push, merge, telemetry or remote processing. Source-only security review; not a full audit.

Baseline: `037ae2cc11e1ce7a1dcdcb95a3b6576b139eb582` (empty repository). Task branch: `feat/browser-redactor`. No project-local instructions existed; project guidance can be added separately with approval.

## Design decision

Compared parse-and-reserialize JSON with source-span replacement. Reserialization is smaller but destroys comments, whitespace and trailing commas. Choose a small JSON/JSONC scanner that validates structure and records value spans, plus dotenv assignment scanning and known-token scanning for other plain text. Native textareas and browser File/Clipboard/Blob APIs avoid editor/framework dependencies. Astro is static shell; TypeScript owns pure redaction and browser interaction. No runtime framework, backend or AI.

## Invariants and limits

- Input is untrusted text, rendered through textarea values/textContent, never HTML.
- Original remains untouched. Output contains only source-span substitutions; no full-document reformatting.
- Detect sensitive key names, common credential patterns, connection-string passwords, URL credentials, bearer tokens and PEM private keys. Preserve ordinary settings, endpoints, ports, public keys and feature flags.
- Same detected secret gets same placeholder within one scan. Mapping never persists or leaves browser.
- JSON/JSONC supports comments and trailing commas; malformed JSON blocks export rather than quietly claiming a complete scan. Generic text scanning is explicitly best-effort.
- Max input 500,000 UTF-16 code units; max file 1 MiB; reject binary/NUL text. Limits bound UI work, not universal parser support. Nesting capped at 100.
- No storage, analytics, external assets, requests carrying inputs, service worker or saved history. Browser extensions and clipboard remain outside app control; clear is not secure memory erasure.
- Detection cannot establish absence of secrets. Permanent review warning; output never called safe. No entropy-only detector or promise to support every file format.

## Observable acceptance

1. Paste/edit or choose/drop a plain-text file; original and redacted preview visible, responsive and keyboard accessible.
2. `.env` quotes, comments, exports, CRLF and multiline quoted values survive except detected value spans.
3. Nested appsettings JSON/JSONC retains keys, comments, indentation, array structure and non-secret values. Sensitive values redact, including numeric values and arrays under sensitive keys.
4. Connection string and URL credentials redact without removing host/database/context. Known provider tokens and private keys redact even without sensitive field names.
5. Preview reports replacement count; copy/download use current output only, with errors surfaced. Download never overwrites source; no automatic clipboard reads.
6. Editing input invalidates previous output immediately; file-read races cannot replace newer edits. Clear removes visible input/output and resets file control.
7. Invalid, binary, oversized or too-deep input has visible error and disabled export. Zero findings still shows review warning.
8. Build has no external runtime assets or input transmission. Production CSP disallows network connections; no secret logging/storage. CSP appropriate for static Astro output.
9. Runnable native Node regression checks cover detection, preservation, false positives, malformed input and limits; production build and browser interaction checks recorded.

## Delivery and rollback

Implement pure engine/tests, static UI, then production build and browser checks using synthetic secrets only. Independent read-only reviewer covers source snapshot, intent, security, sufficiency, accessibility and simplicity. Fix blockers and recheck at most twice. Commit only verified/reviewed task changes. Retain branch/worktrees; rollback by selecting baseline, never delete user files.

## Verification and review

Author checks: `npm test` (19 native Node tests pass); `npm run build` (Astro 6.4.8 production build passes, no warnings). Initial outdated experimental CSP flag corrected to stable `security.csp`. No standalone TypeScript compiler installed; Astro build transpiles but is not a full typecheck.

Guest Chromium against loopback production preview: example, live edits, malformed JSON clears output/disables exports, clear, 390px layout without overflow, UTF-8 file chooser, binary rejection, download filename, clipboard success, empty local/session storage pass. Network capture contains local document/script GETs only, no external calls or input transmission. Production CSP includes `connect-src 'none'`. Initial missing favicon fixed. Additional Chromium checks pass: delayed file-read race (new edits win), exports disabled during read, invalid UTF-8, oversized file, clipboard failure, keyboard Enter on Clear, file drop, text-drop default preserved, outside file-drop navigation blocked, download failure. No page errors on updated build.

Independent reviewer: supervisor `t13m`, reviewer `t13r` (`redactor-child-review`), isolated detached worktree `/Users/wolter/.local/share/pi-worktrees/key-redactor/review-browser-redactor`. Reviewed initial immutable Git tree `7622b56651f64e9da2a4f305648d2cd5d55445ff`. Source-only security guidance review; OS sandbox required for independent target execution unavailable, so reviewer ran no app/tests/browser. Author functional checks are not an independent runtime security audit.

Initial verdict changes required: M1 punctuation tails in connection-string passwords, M2 empty-username Redis and embedded @ URL passwords, M3 JSONC comment credentials, M4 common key/provider patterns. All accepted and fixed with regressions. Minor findings: preserve .NET localdb host via span-local escape fallback; share detection patterns; prevent cross-string known-pattern matches; linear placeholder allocation; tolerate plain-text stray quotes; preserve Auth section metadata; preserve text drops and prevent file navigation with visible drag state; reduce repeated live announcements and associate input errors; record evidence and hosting limitations. Applied these corrections except file-read cancellation messaging: newer edits/format changes intentionally win, silently, rather than announce stale asynchronous results. Copy/download/file chooser/binary functional evidence added after initial reviewer brief.

Recheck 1 of tree `de2d60cae25d50d7335dbafa4192c24d317ecfb3` confirmed initial fixes and source-supported JSON validity; changes required for empty password line consuming next line (R1), Docker/npm auth regression (R2), client-key-data gap (R3). All fixed with regressions: horizontal whitespace only, auth/auths sensitivity with metadata child exclusions, keydata suffix. Minor fixes: escaped generic passwords redact to line end, adjacent escape widens JSON token span, Basic requires case-sensitive base64-looking value, URL credential lengths bounded. Unclosed PEM mentions intentionally block as fail-closed UX cost. Final recheck 2 accepted exact source tree `850312d7a7ba86c8f236a6e4fd5c1b7f8860ad0f`: zero blocking/major findings. Reviewer verified snapshot hash; source unchanged by reviewer. Four nonblocking residuals deferred to avoid changing reviewed code after authorized final round: generic escaped-password fallback can consume closing quote/punctuation; metadata-named URLs under sensitive parents can hide webhooks/SAS credentials; capitalized Basic prose can over-redact; URL scheme matching still has adversarial performance ceiling. These are not guarantees covered by detection. Revisit with focused regressions before expanding format support. No code changes after acceptance; only this delivery evidence updated. Final Chromium recheck confirmed example, empty assignment, Redis redaction, computed CSS loaded and production CSP.

All acceptance items have source/test evidence within documented best-effort limits. Functional tests are author-run, not independently sandboxed security validation. Final delivery is local-only, no push/merge/deployment. README includes startup commands; original main checkout remains baseline because integration was not authorized.

Remaining deliberate limits: source-span escaped credential fallback may redact whole JSON string; unknown formats best-effort; no verified secure erasure; no full audit. A meta CSP cannot enforce `frame-ancestors`; future static host should set `Content-Security-Policy: frame-ancestors 'none'` and standard security headers. No host deployment in scope.
