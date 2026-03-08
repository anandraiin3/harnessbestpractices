# Harness Best Practices — Centralized Template Repository

This repository is the **single source of truth** for all shared Harness
artefacts: pipeline templates, stage/step-group templates, step templates,
OPA policies, and governance policy sets.

Application-specific pipelines live with their application repos and
**reference** templates here via `templateRef`.

---

## Repository Structure

```
harnessbestpractices/
│
├── templates/
│   ├── pipeline/                          # Pipeline templates
│   │   └── dotnet-aks-build-deploy/       # .NET → ACR → AKS (canary + rolling)
│   │       └── pipeline-template.yaml
│   │
│   ├── stepgroup/                         # Step-group templates
│   │   ├── ai-code-quality/               # AI code quality scanner (CI stage)
│   │   │   └── stepgroup-template.yaml    # org.Check_Code_Quality_Using_AI
│   │   └── opa-code-quality-enforcement/  # OPA policy gate (Custom stage)
│   │       └── stepgroup-template.yaml    # org.Enforce_Code_Quality_Checks
│   │
│   └── step/                              # Individual step templates
│       └── cv-verify/                     # Dynatrace CV verify step
│           └── step-template.yaml
│
├── policies/
│   ├── opa/                               # OPA Rego policy definitions
│   │   └── code-quality/
│   │       └── codequalitypolicy.rego
│   └── governance/                        # Harness policy set YAMLs
│
├── environments/                          # Shared environment definitions
├── services/                              # Shared service definitions
└── README.md
```

---

## Template Registry

| Template | Identifier | Type | Version | Description |
|---|---|---|---|---|
| .NET AKS Build & Deploy | `HelloWorldDotNet_Build_and_Deploy` | Pipeline | v1 | CI + canary/rolling deploy to AKS with Dynatrace CV |
| AI Code Quality | `Check_Code_Quality_Using_AI` | StepGroup | v4 | Anthropic/OpenAI code scanner; standard + full-audit modes |
| OPA Code Quality Enforcement | `Enforce_Code_Quality_Checks` | StepGroup | v2 | OPA policy gate for AI scan results (Custom stage) |
| CV Dynatrace Verify | `CV_Dynatrace_Health_Check` | Step | v1 | Reusable Dynatrace continuous verification step |

---

## Conventions

### Versioning
- Templates use `versionLabel: vN` (e.g. `v1`, `v2`, `v3`).
- Bump the version for every breaking change. Non-breaking additions can go
  to the same version with a new commit.
- Keep old versions in Harness — do **not** delete them until all consumers
  have migrated.

### Naming
| Artefact | Pattern | Example |
|---|---|---|
| Template name | Title Case, descriptive | `AI Code Quality Check` |
| Template identifier | PascalCase, no spaces | `Check_Code_Quality_Using_AI` |
| File | kebab-case | `stepgroup-template.yaml` |
| Folder | kebab-case | `ai-code-quality/` |

### Scope
- **Org-level** (`orgIdentifier: default`, no `projectIdentifier`): all
  templates and policies in this repo. This makes them referenceable across
  all projects as `org.<identifier>`.
- **Account-level**: not used here — reserved for truly global connectors.

### Reference from application pipelines
```yaml
# In your application pipeline / pipeline YAML:
stepGroup:
  template:
    templateRef: org.Check_Code_Quality_Using_AI
    versionLabel: v4
```

---

## Contributing

1. **New template** — create a folder under the appropriate `templates/`
   sub-directory, add the YAML, and register it in the table above.
2. **New policy** — add the `.rego` file under `policies/opa/<topic>/` and
   reference it from the matching governance policy set.
3. **Breaking change** — bump `versionLabel`, update this README, and open
   a PR with migration notes.
4. All PRs require review from the platform team before merge to `main`.
