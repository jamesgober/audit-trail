# audit-trail - Project Prompt

## Priority order

1. `REPS.md` - SUPREME AUTHORITY
2. `.dev/DIRECTIVES.md`
3. This file (`.dev/PROMPT.md`)
4. `.dev/ROADMAP.md`

## What this crate is

Structured audit logging with tamper-evident chaining. Every write produces a cryptographically linked record (hash chain). Compliance-grade output (who, what, when, where, result). Pluggable backends. Foundation for HIPAA, SOC 2, and PCI-DSS compliance.

## Why it exists

Cryptographically chained records (who, what, when, where, result). Compliance-grade output for HIPAA, SOC 2, PCI-DSS. Pluggable backends.

## Skill areas

- hash chaining
- audit log integrity
- compliance frameworks
- structured logging

## Scope (1.0)

Defined in `.dev/ROADMAP.md`.

## Out of scope (always)

- Features requiring async runtime hard-dependency
- Features pulling in heavy framework dependency
- Features that violate REPS

## Pre-1.0 audit (mandatory)

See `.dev/ROADMAP.md` for the audit checklist. Must verify:

- Feature completeness vs. the roadmap
- API accuracy and stability
- Code cleanliness
- Error hardening
- Documentation completeness
- Test coverage
- Benchmark coverage
- Cross-platform CI passing

## Versioning

Fast-track. No slow-stepping:

- 0.1.0 - scaffold
- 0.2.0 - first real implementation
- 0.5.0 - most features in place
- 0.9.0 - feature-complete, hardening
- 0.9.x - audit findings
- 1.0.0 - stable