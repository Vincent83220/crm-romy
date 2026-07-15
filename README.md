# CRM Les Ami(e)s de Romy

CRM association pour la prevention des violences infantiles.
FastAPI + PWA mobile-first. Raspberry Pi via Tailscale (port 8001).

## Version actuelle: v1.28

24 onglets, ~100 endpoints API.

## Structure

- `main.py` — Backend FastAPI (~2970 lignes)
- `static/index.html` — Frontend PWA (~3100 lignes)
- `auth_config.template.json` — Template auth (secrets a remplir)
- `smtp_config.template.json` — Template SMTP (secrets a remplir)

## Restauration

1. `git clone https://github.com/Vincent83220/crm-romy.git`
2. Copier vers `C:\Users\<user>\Desktop\CRM Romy\`
3. Recreer `auth_config.json` depuis le template (ou recuperer depuis le Pi: `/home/hermes_app/crm_romy/auth_config.json`)
4. Recreer `smtp_config.json` depuis le template
5. Recuperer `db.json` depuis le Pi: `/home/hermes_app/crm_romy/db.json`
6. Deployer: `python -c "import paramiko; ..."` (voir skill crm-asso)

## Infrastructure

- Pi: 100.89.45.97:8001 (Tailscale)
- Service: crm_romy.service (systemd)
- Dossier Pi: /home/hermes_app/crm_romy/
