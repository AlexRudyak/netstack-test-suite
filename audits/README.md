# Audits

Point-in-time reviews of this codebase, each run against a whole-repository
read rather than a diff. Every audit records the commit it was taken at, the
method used, a severity scale, and — once its findings have been applied — a
status table mapping each finding to the commit that fixed it. The original
analysis stays in the file alongside the fix, so the record of *what was
wrong and why* survives the change.

| Audit | Taken at | Status |
|---|---|---|
| [Code complexity](code-complexity-audit.md) | `7100ad0` | applied |
| [Code duplication](code-duplication-audit.md) | `db76783` | applied |
| [Design patterns](design-patterns-audit.md) | `cbe4af1` | 14 of 16 applied; 2 no-action by design |
| [Error handling](error-handling-audit.md) | `4653b25` | applied |

## Prompt source

The review prompts these audits were produced from come from Jeremy Morgan's
**Claude-Code-Reviewing-Prompts** collection:

<https://github.com/JeremyMorgan/Claude-Code-Reviewing-Prompts>

The prompts supplied the review dimensions and the reporting shape — the
severity rating, the "cite exact locations, prefer drop-in fixes, mark
anything unverifiable" constraints. The findings themselves are specific to
this repository, and the prompts' framing was adapted where it did not fit:
the error-handling prompt asks for HTTP status categorisation (400/401/403/
404/429/500), which this package has no equivalent for — it exposes no
request/response service — so that audit substitutes the categories this
codebase actually has and says so explicitly rather than inventing a mapping.
