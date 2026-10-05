# SecureGuard migration map

## Existing extension → new architecture

| Existing component | New location | Strategy |
|---|---|---|
| `background/alertManager.js` | `apps/api/src/alerts` + extension notification adapter | Move persistence/business rules to API; keep browser notification locally |
| `background/requestAnalyzer.js` | `apps/extension/src/core` + `apps/api/src/analysis` | Local metadata extraction first; server-side enrichment later |
| `background/reputationEngine.js` | `apps/extension/src/core/reputation` + API rules | Keep fast local checks; centralize updateable reputation rules |
| `background/headerAnalyzer.js` | `apps/extension/src/core` | Local header risk evaluation |
| `background/scanner.js` | `apps/extension/src/core/risk-engine.ts` + API analysis modules | Split detection from persistence |
| `background/storageManager.js` | PostgreSQL via Prisma + extension local cache | Replace Chrome storage as system of record |
| `content/formScanner.js` | `apps/extension/src/core` | Preserve local form detection |
| `content/fileScanner.js` | `apps/extension/src/core` | Preserve local file metadata scanning |
| `content/overlay.js` | React extension UI | Replace imperative DOM overlay with component UI |
| `popup/*` | React extension UI | Rebuild as React components |
| `options/*` | React extension settings | Rebuild as React components |

## Privacy rule

Do not upload passwords, API keys, card numbers, tokens, or other raw secrets. The extension should classify sensitive content locally and send only the minimum metadata required for analytics, policy, or threat intelligence.

## Migration phases

1. Port the remaining scanners and reputation logic to TypeScript without changing behavior.
2. Rebuild popup/options as React extension pages.
3. Implement API persistence and authentication.
4. Expand PostgreSQL schema for users, alerts, websites, settings and scan history.
5. Add dashboard analytics.
6. Add automated unit/integration tests.
7. Harden permissions, CSP, API authentication and deployment configuration.
