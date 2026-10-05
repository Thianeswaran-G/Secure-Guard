# SecureGuard v4 — Phase 2 overlay

This archive contains only files to overlay onto the existing SecureGuard v4 project. It is not a replacement project and contains no node_modules.

Changes: alerts API, settings API, whitelist API, scan summary, offline scan queue, improved extension background handling, and upgraded dashboard.

After copying these files into your existing project root, run:

```powershell
npm run db:generate
npm run db:migrate -- --name phase2
npm run typecheck
npm run build:extension
```

No npm install is required for this phase.
