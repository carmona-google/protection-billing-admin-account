# Protection Billing Admin Account (`Billing Broker` & Security Watchdog)

Reference architecture, risk analysis, executive advisory, visual diagrams, and Terraform / Cloud Run reference implementation for eliminating standing `roles/billing.admin` and `roles/billing.user` privileges in Google Cloud Partner/Customer environments—preventing external *Made-for-Abuse* project linking and *LLMjacking* attacks.

## Repository Contents

| Path | Description |
| :--- | :--- |
| [hld_partner_billing_automation.md](hld_partner_billing_automation.md) | **High-Level Design (`v1.1`)**: Dual-Mode Brokered Linking (**Mode A** 30m ephemeral project grant + **Mode B** folder-scoped OIDC/Terraform), REST `v1` contracts, Firestore data model, IAM/PAM matrix, and Two-Tier `<10s` Security Watchdog. |
| [risk_analysis_and_email_audit.md](risk_analysis_and_email_audit.md) | **Risk Analysis & Advisory Audit**: Deep-dive into `roles/billing.admin` / `roles/billing.user` hijack mechanics and 8 critical gaps in customer mitigation advisories. |
| [diagrams/](diagrams/) | Standalone vector (`.svg`) and 2x Retina (`.png`) architecture, Dual-Mode workflow, state-machine, and kill-chain diagrams. |
| [reference-implementation/](reference-implementation/README.md) | **Terraform & Cloud Run Reference Implementation**: Partner control plane IaC, customer Mode B Terraform module, FastAPI Broker & Watchdog services, and brownfield backfill CLI. |
| [demo_casos_de_uso_partner.md](demo_casos_de_uso_partner.md) | **Guided Partner Demo Playbook**: Step-by-step live walkthrough for Mode A (`EPHEMERAL_PROJECT`), attack simulation (*Made-for-Abuse* block), Mode B (`FOLDER_DELEGATED`), Velocity Gate, and `<10s` Security Watchdog. |
