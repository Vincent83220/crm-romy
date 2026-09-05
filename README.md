# CRM Les Ami(e)s de Romy

CRM association pour la prevention des violences infantiles.
FastAPI + PWA mobile-first. Deploye en Docker sur mini-PC Nipogi AM06 (port 8001).

## Version actuelle: v1.34

- 24 onglets, **142 endpoints API**
- Backend FastAPI (~5 137 lignes)
- Frontend PWA (~5 413 lignes)
- **Nouveautes v1.34** :
  - OCR factures integre via Tesseract (fra+eng, local, sans Ollama) — extraction automatique des donnees de factures (montant, fournisseur, date, SIRET...)
  - Module subventions (modeles v1.34)
  - Deploiement Docker sur Nipogi (permissions uploads/backups/db.json corrigees)

## Structure

- `main.py` — Backend FastAPI
- `static/index.html` — Frontend PWA
- `auth_config.template.json` — Template auth (secrets a remplir)
- `smtp_config.template.json` — Template SMTP (secrets a remplir)

## Restauration

1. `git clone https://github.com/Vincent83220/crm-romy.git`
2. Copier vers le dossier de travail
3. Recreer `auth_config.json` depuis le template (ou recuperer depuis le Nipogi: `/home/hermes_app/docker-stack/crm-romy/auth_config.json`)
4. Recreer `smtp_config.json` depuis le template
5. Recuperer `db.json` depuis le Nipogi: `/home/hermes_app/docker-stack/crm-romy/db.json`
6. Deployer: `docker compose up -d --build crm-romy` (voir skill server-docker-deploy)

## Infrastructure

- **Nipogi AM06** : 100.74.83.35:8001 (Tailscale) — conteneur Docker `crm-romy`, restart always
- HTTPS public : amiesderomy.duckdns.org (Nginx + Let's Encrypt)
- Backup quotidien chiffre (AES-256) vers le Pi (100.89.45.97, offsite)
- Historique : ancien deploiement Raspberry Pi (systemd, decommissionne le 04/09/2026)