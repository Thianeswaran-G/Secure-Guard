# SecureGuard

SecureGuard is being migrated from a JavaScript-only Chrome extension into a modular full-stack security platform.

## Target architecture

- Chrome Extension: TypeScript + Manifest V3
- Web Dashboard: React + TypeScript + Vite
- API: NestJS + TypeScript
- Database: PostgreSQL
- ORM: Prisma
- Shared contracts: TypeScript package
- Security principle: sensitive content is analyzed locally whenever possible; the API receives security metadata rather than raw secrets.

## Repository layout

```text
apps/
  extension/  Chrome extension and local security engine
  web/        React dashboard
  api/        NestJS backend
packages/
  shared/     Shared DTOs, enums and types
infra/
  database/   Database setup and migrations/schema
 docs/         Architecture and migration notes
```

## Migration status

Phase 1 scaffold + migration mapping is included. Existing SecureGuard behavior is being moved feature-by-feature rather than copied as-is.
