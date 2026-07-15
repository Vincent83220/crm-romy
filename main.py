"""
CRM Association "Les Ami(e)s de Romy"
Backend FastAPI - multi-utilisateurs, audit trail, emailing, événements, documents
Déploiement: Raspberry Pi (Tailscale) + Windows local
"""

import json
import os
import re
import smtplib
import time
import threading
import hashlib
import secrets
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, Response, HTTPException, Depends, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ============ CONFIG ============
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "db.json"
BACKUP_DIR = BASE_DIR / "backups"
AUTH_PATH = BASE_DIR / "auth_config.json"
SMTP_PATH = BASE_DIR / "smtp_config.json"
DOCS_DIR = BASE_DIR / "uploads"
BACKUP_DIR.mkdir(exist_ok=True)
DOCS_DIR.mkdir(exist_ok=True)

VERSION = "1.28"
HOST = os.environ.get("CRM_HOST", "100.89.45.97")
PORT = int(os.environ.get("CRM_PORT", "8001"))

# ============ AUTH ============
def load_auth():
    with open(AUTH_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def load_smtp():
    try:
        with open(SMTP_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        # Support base64-encoded password (security: not in plaintext)
        if "password_b64" in cfg and not cfg.get("password"):
            cfg["password"] = base64.b64decode(cfg["password_b64"]).decode("utf-8")
        return cfg
    except Exception:
        return {"password": ""}

def get_user_from_token(token: str):
    auth = load_auth()
    for u in auth["users"]:
        if u["token"] == token:
            return u
    return None

def require_auth(request: Request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token requis")
    token = auth_header[7:]
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Token invalide")
    return user

def require_admin(user=Depends(require_auth)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Acces admin requis")
    return user

REFERENT_ROLES = {"admin", "referent"}

def require_referent(user=Depends(require_auth)):
    """Referent or admin only. Members get 403."""
    if user["role"] not in REFERENT_ROLES:
        raise HTTPException(status_code=403, detail="Acces referent requis")
    return user

def is_member(user):
    return user["role"] == "membre"

def is_referent_or_admin(user):
    return user["role"] in REFERENT_ROLES

# ============ PASSWORD HASHING (pbkdf2) ============
def hash_password(password: str, salt: str = None):
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return key.hex(), salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    key, _ = hash_password(password, salt)
    return secrets.compare_digest(key, stored_hash)

def migrate_plaintext_passwords():
    """Auto-hash plaintext passwords on startup."""
    auth = load_auth()
    changed = False
    for u in auth["users"]:
        if "password" in u and "password_hash" not in u:
            pwd = u.pop("password")
            h, s = hash_password(pwd)
            u["password_hash"] = h
            u["password_salt"] = s
            changed = True
    if changed:
        with open(AUTH_PATH, "w", encoding="utf-8") as f:
            json.dump(auth, f, ensure_ascii=False, indent=2)
        print("[SECURITY] Mots de passe migrés vers hash pbkdf2")

# ============ RATE LIMITING (login) ============
_login_attempts = {}
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW = 300  # 5 minutes

def check_login_rate_limit(client_ip: str):
    now = time.time()
    if client_ip in _login_attempts:
        _login_attempts[client_ip] = [t for t in _login_attempts[client_ip] if now - t < _LOGIN_WINDOW]
        if len(_login_attempts[client_ip]) >= _LOGIN_MAX_ATTEMPTS:
            raise HTTPException(status_code=429, detail="Trop de tentatives. Reessayez dans 5 minutes.")
    else:
        _login_attempts[client_ip] = []

def record_failed_login(client_ip: str):
    if client_ip not in _login_attempts:
        _login_attempts[client_ip] = []
    _login_attempts[client_ip].append(time.time())

def clear_login_attempts(client_ip: str):
    _login_attempts.pop(client_ip, None)

# ============ DB (atomic write + recovery) ============
_db_lock = threading.Lock()

def load_db():
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            return json.loads(f.read(), strict=False)
    except json.JSONDecodeError:
        # Try recovery from backup
        latest = _find_latest_valid_backup()
        if latest:
            with open(latest, "r", encoding="utf-8") as f:
                return json.loads(f.read(), strict=False)
        return {"contacts": [], "evenements": [], "documents": []}
    except FileNotFoundError:
        return {"contacts": [], "evenements": [], "documents": []}

def save_db(data):
    with _db_lock:
        tmp = DB_PATH.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, DB_PATH)

def backup_db():
    with _db_lock:
        if not DB_PATH.exists():
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        bk = BACKUP_DIR / f"db_backup_{ts}.json"
        tmp = bk.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(load_db(), f, ensure_ascii=False, indent=2)
        os.replace(tmp, bk)
        # Keep only last 30 backups
        backups = sorted(BACKUP_DIR.glob("db_backup_*.json"))
        for old in backups[:-30]:
            old.unlink(missing_ok=True)

def _find_latest_valid_backup():
    backups = sorted(BACKUP_DIR.glob("db_backup_*.json"), reverse=True)
    for bk in backups:
        try:
            with open(bk, "r", encoding="utf-8") as f:
                d = json.loads(f.read(), strict=False)
            if d.get("contacts"):
                return bk
        except Exception:
            continue
    return None

def validate_db_integrity():
    data = load_db()
    if not data.get("contacts") and not data.get("evenements") and not data.get("documents"):
        latest = _find_latest_valid_backup()
        if latest:
            with open(latest, "r", encoding="utf-8") as f:
                data = json.loads(f.read(), strict=False)
            save_db(data)
            print(f"[RECOVERY] Base restaurée depuis {latest.name}")
    return data

# ============ MODELS ============
class LoginRequest(BaseModel):
    username: str
    password: str

class ContactUpdate(BaseModel):
    prenom: str = ""
    nom: str = ""
    qualite: str = ""
    telephone: str = ""
    email: str = ""
    notes: str = ""
    tags: str = ""  # tags separes par virgules

class ContactCreate(ContactUpdate):
    pass

class HistoriqueEntry(BaseModel):
    action: str
    details: str = ""

class EvenementCreate(BaseModel):
    titre: str
    date: str
    heure: str = ""
    lieu: str = ""
    description: str = ""
    participants: list[str] = []

class EvenementUpdate(BaseModel):
    titre: Optional[str] = None
    date: Optional[str] = None
    heure: Optional[str] = None
    lieu: Optional[str] = None
    description: Optional[str] = None
    participants: Optional[list[str]] = None
    presence: Optional[dict] = None  # {contact_id: "present"|"absent"|"excuse"|""}

class CotisationCreate(BaseModel):
    contact_id: str
    annee: str  # ex "2026"
    montant: float = 0.0
    date_paiement: str = ""  # YYYY-MM-DD
    mode_paiement: str = ""  # especes, cheque, virement
    statut: str = "paye"  # paye, en_attente, impaye
    notes: str = ""

class CotisationUpdate(BaseModel):
    montant: Optional[float] = None
    date_paiement: Optional[str] = None
    mode_paiement: Optional[str] = None
    statut: Optional[str] = None
    notes: Optional[str] = None

class TacheCreate(BaseModel):
    titre: str
    description: str = ""
    assigne_a: str = ""  # contact_id
    echeance: str = ""  # YYYY-MM-DD
    priorite: str = "normale"  # basse, normale, haute, urgente

class TacheUpdate(BaseModel):
    titre: Optional[str] = None
    description: Optional[str] = None
    assigne_a: Optional[str] = None
    echeance: Optional[str] = None
    priorite: Optional[str] = None
    statut: Optional[str] = None  # a_faire, en_cours, terminee

class DonCreate(BaseModel):
    contact_id: str = ""
    nom: str = ""
    montant: float = 0.0
    date: str = ""
    mode_paiement: str = ""
    type_don: str = "don"  # don, sponsor, subvention
    notes: str = ""

class FeedbackCreate(BaseModel):
    type: str = "bug"  # bug, suggestion, autre
    message: str
    page: str = ""  # sur quelle page/view

class EmailSend(BaseModel):
    subject: str
    body: str
    recipients: list[str] = []
    contact_ids: list[str] = []
    template: str = ""
    html: bool = False

class DocumentCreate(BaseModel):
    nom: str
    type_doc: str = ""
    description: str = ""

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "editeur"
    contact_id: str = ""  # for membre role: link to their contact record

class UserUpdate(BaseModel):
    password: Optional[str] = None
    role: Optional[str] = None
    contact_id: Optional[str] = None

class PresenceSelf(BaseModel):
    """Member self-registration for an event."""
    contact_id: str
    presence: str = "present"  # present, absent, excuse, ""

# ============ MODELS V1.26 — nouvelles fonctions ============
class AccompagnementCreate(BaseModel):
    contact_id: str
    type_suivi: str = "accompagnement"  # accompagnement, suivi famille, orientation, signalement
    date_debut: str = ""  # YYYY-MM-DD
    date_fin: str = ""
    statut: str = "actif"  # actif, clos, suspendu
    priorite: str = "normale"  # basse, normale, haute, urgente
    intervenants: list[str] = []  # contact_ids des référents
    notes_confidentielles: str = ""
    notes_partagees: str = ""

class AccompagnementUpdate(BaseModel):
    type_suivi: Optional[str] = None
    date_debut: Optional[str] = None
    date_fin: Optional[str] = None
    statut: Optional[str] = None
    priorite: Optional[str] = None
    intervenants: Optional[list[str]] = None
    notes_confidentielles: Optional[str] = None
    notes_partagees: Optional[str] = None

class AccompagnementNote(BaseModel):
    note: str
    confidentiel: bool = False

class BenevolePlanning(BaseModel):
    evenement_id: str
    contact_id: str
    role: str = "participant"  # participant, responsable, animateur, logistique
    creneau: str = ""  # ex: "matin", "apres-midi", "09:00-12:00"

# ============ MODELS V1.27 — gestion quotidienne ============
class NoteFraisCreate(BaseModel):
    contact_id: str = ""  # qui a engage la depense
    date: str = ""  # YYYY-MM-DD
    montant: float = 0.0
    categorie: str = ""  # deplacement, repas, fournitures, communication, autre
    description: str = ""
    justificatif: str = ""  # nom du fichier upload
    statut: str = "en_attente"  # en_attente, valide, rembourse

class NoteFraisUpdate(BaseModel):
    montant: Optional[float] = None
    categorie: Optional[str] = None
    description: Optional[str] = None
    statut: Optional[str] = None

class EcheanceCreate(BaseModel):
    titre: str
    date: str = ""  # YYYY-MM-DD
    type_echeance: str = "administratif"  # administratif, fiscal, assurance, ag, reunion, autre
    description: str = ""
    recursif: str = ""  # annuel, mensuel, "" (vide = ponctuel)
    responsable: str = ""

class EcheanceUpdate(BaseModel):
    titre: Optional[str] = None
    date: Optional[str] = None
    type_echeance: Optional[str] = None
    description: Optional[str] = None
    recursif: Optional[str] = None
    responsable: Optional[str] = None
    statut: Optional[str] = None  # a_venir, fait, en_retard

class RegistreAppelCreate(BaseModel):
    contact_id: str = ""  # contact appele (si dans la base)
    nom_appelant: str = ""
    nom_appele: str = ""
    date_appel: str = ""  # YYYY-MM-DD
    heure: str = ""
    motif: str = ""  # information, demande aide, signalement, suivi, autre
    description: str = ""
    suite_donnee: str = ""

class VoteCreate(BaseModel):
    titre: str
    date: str = ""  # YYYY-MM-DD
    type_vote: str = "ag"  # ag, ca, bureau
    description: str = ""

class VoteResultat(BaseModel):
    pour: int = 0
    contre: int = 0
    abstention: int = 0
    notes: str = ""

class ChecklistCreate(BaseModel):
    titre: str
    type_checklist: str = "evenement"  # evenement, cloture_exercice, ag, import_excel, autre
    taches: list[str] = []  # liste des items a cocher
    evenement_id: str = ""

class ChecklistUpdate(BaseModel):
    taches: Optional[list[str]] = None
    coche: Optional[list[bool]] = None

# ============ MODELS V1.28 — communication & gestion ============
class SondageCreate(BaseModel):
    question: str
    options: list[str] = []  # choix possibles
    cible: str = "membres"  # membres, referents, tous
    date_fin: str = ""  # YYYY-MM-DD
    multiple: bool = False  # reponses multiples autorisees

class SondageReponse(BaseModel):
    option_index: int  # index dans options

class CompteRenduCreate(BaseModel):
    titre: str
    date: str = ""  # YYYY-MM-DD
    type_reunion: str = "reunion"  # reunion, ag, ca, bureau
    presents: list[str] = []  # contact_ids
    absents: list[str] = []
    excused: list[str] = []
    ordre_du_jour: str = ""
    discussions: str = ""
    decisions: str = ""
    actions: str = ""  # actions a suivre

class CompteRenduUpdate(BaseModel):
    titre: Optional[str] = None
    date: Optional[str] = None
    type_reunion: Optional[str] = None
    presents: Optional[list[str]] = None
    absents: Optional[list[str]] = None
    excused: Optional[list[str]] = None
    ordre_du_jour: Optional[str] = None
    discussions: Optional[str] = None
    decisions: Optional[str] = None
    actions: Optional[str] = None

class SmsCampaignCreate(BaseModel):
    message: str
    destinataires: list[str] = []  # numeros de telephone
    contact_ids: list[str] = []  # ou par contact_id
    qualite: str = ""  # ou par groupe qualite

class PresseContactCreate(BaseModel):
    nom: str
    media: str = ""  # nom du media
    fonction: str = ""  # journaliste, redacteur, etc.
    email: str = ""
    telephone: str = ""
    notes: str = ""

class PresseReleaseCreate(BaseModel):
    sujet: str
    date: str = ""
    media_cible: str = ""  # nom du media ou "tous"
    contacts_envoyes: list[str] = []  # presse_contact_ids
    contenu: str = ""
    statut: str = "brouillon"  # brouillon, envoye, publie

class PresseCouvertureCreate(BaseModel):
    titre: str
    media: str = ""
    date: str = ""
    type_couverture: str = "article"  # article, emission, interview, mention
    lien: str = ""
    resume: str = ""

class MembreProfilUpdate(BaseModel):
    telephone: Optional[str] = None
    email: Optional[str] = None
    ville: Optional[str] = None
    code_postal: Optional[str] = None

# ============ APP ============
app = FastAPI(title="CRM Les Ami(e)s de Romy")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://100.89.45.97:8001", "http://localhost:8001", "http://127.0.0.1:8001"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ============ SECURITY HEADERS MIDDLEWARE ============
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    return response

# ============ HELPERS ============
def now_iso():
    return datetime.now().isoformat()

def normalize_phone(val):
    if not val:
        return ""
    digits = re.sub(r'\D', '', str(val))
    if len(digits) == 9 and digits[0] in '67':
        digits = '0' + digits
    if len(digits) == 10:
        return f"{digits[0:2]} {digits[2:4]} {digits[4:6]} {digits[6:8]} {digits[8:10]}"
    return str(val).strip()

def add_history(contact, user, action, details=""):
    entry = {
        "date": now_iso(),
        "user": user["username"],
        "action": action,
        "details": details
    }
    contact.setdefault("historique", []).append(entry)
    contact["modifie_par"] = user["username"]
    contact["modifie_le"] = entry["date"]

def gen_id(prefix="romy"):
    data = load_db()
    existing = {c["id"] for c in data["contacts"]}
    n = len(data["contacts"]) + 1
    while f"{prefix}-{n:03d}" in existing:
        n += 1
    return f"{prefix}-{n:03d}"

def send_email_smtp(to_emails, subject, body, attachments=None, html=False):
    smtp = load_smtp()
    if not smtp.get("password"):
        raise HTTPException(status_code=400, detail="SMTP non configure (smtp_config.json)")
    
    msg = MIMEMultipart()
    msg["From"] = "vincentminvielle@gmail.com"
    msg["To"] = ", ".join(to_emails)
    msg["Subject"] = subject
    
    if html:
        msg.attach(MIMEText(body, "html", "utf-8"))
    else:
        msg.attach(MIMEText(body, "plain", "utf-8"))
    
    if attachments:
        for filepath in attachments:
            if not os.path.exists(filepath):
                continue
            with open(filepath, "rb") as f:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f'attachment; filename="{os.path.basename(filepath)}"')
                msg.attach(part)
    
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login("vincentminvielle@gmail.com", smtp["password"])
        server.sendmail("vincentminvielle@gmail.com", to_emails, msg.as_string())

# ============ AUTH ENDPOINTS ============
@app.post("/auth/login")
async def login(req: LoginRequest, request: Request):
    if not isinstance(req.username, str) or not isinstance(req.password, str):
        raise HTTPException(status_code=422, detail="Types invalides")
    client_ip = request.client.host if request.client else "unknown"
    check_login_rate_limit(client_ip)
    auth = load_auth()
    for u in auth["users"]:
        if u["username"] == req.username:
            stored_hash = u.get("password_hash")
            stored_salt = u.get("password_salt")
            if stored_hash and stored_salt:
                if verify_password(req.password, stored_hash, stored_salt):
                    clear_login_attempts(client_ip)
                    return {"status": "ok", "username": u["username"], "role": u["role"], "token": u["token"], "contact_id": u.get("contact_id", "")}
            elif u.get("password") == req.password:
                # Legacy plaintext - migrate on successful login
                h, s = hash_password(req.password)
                u.pop("password", None)
                u["password_hash"] = h
                u["password_salt"] = s
                with open(AUTH_PATH, "w", encoding="utf-8") as f:
                    json.dump(auth, f, ensure_ascii=False, indent=2)
                clear_login_attempts(client_ip)
                return {"status": "ok", "username": u["username"], "role": u["role"], "token": u["token"], "contact_id": u.get("contact_id", "")}
            record_failed_login(client_ip)
            raise HTTPException(status_code=401, detail="Identifiants invalides")
    record_failed_login(client_ip)
    raise HTTPException(status_code=401, detail="Identifiants invalides")

@app.get("/auth/verify")
async def verify_token(token: str = Query(...)):
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Token invalide")
    return {"status": "ok", "username": user["username"], "role": user["role"], "contact_id": user.get("contact_id", "")}

@app.get("/auth/users")
async def list_users(user=Depends(require_admin)):
    auth = load_auth()
    return [{"username": u["username"], "role": u["role"], "contact_id": u.get("contact_id", "")} for u in auth["users"]]

@app.post("/auth/users")
async def create_user(req: UserCreate, user=Depends(require_admin)):
    auth = load_auth()
    if any(u["username"] == req.username for u in auth["users"]):
        raise HTTPException(status_code=409, detail="Utilisateur existe deja")
    import secrets
    token = f"romy-{req.role}-" + secrets.token_hex(8)
    pwd_hash, pwd_salt = hash_password(req.password)
    new_user = {"username": req.username, "password_hash": pwd_hash, "password_salt": pwd_salt, "role": req.role, "token": token}
    if req.contact_id:
        new_user["contact_id"] = req.contact_id
    auth["users"].append(new_user)
    with open(AUTH_PATH, "w", encoding="utf-8") as f:
        json.dump(auth, f, ensure_ascii=False, indent=2)
    return {"status": "ok", "username": req.username, "role": req.role}

@app.put("/auth/users/{username}")
async def update_user(username: str, req: UserUpdate, user=Depends(require_admin)):
    auth = load_auth()
    for u in auth["users"]:
        if u["username"] == username:
            if req.password:
                h, s = hash_password(req.password)
                u["password_hash"] = h
                u["password_salt"] = s
                u.pop("password", None)
            if req.role:
                u["role"] = req.role
            if req.contact_id is not None:
                u["contact_id"] = req.contact_id
            with open(AUTH_PATH, "w", encoding="utf-8") as f:
                json.dump(auth, f, ensure_ascii=False, indent=2)
            return {"status": "ok"}
    raise HTTPException(status_code=404, detail="Utilisateur non trouve")

@app.delete("/auth/users/{username}")
async def delete_user(username: str, user=Depends(require_admin)):
    if username == "vincent":
        raise HTTPException(status_code=403, detail="Impossible de supprimer l'admin principal")
    auth = load_auth()
    auth["users"] = [u for u in auth["users"] if u["username"] != username]
    with open(AUTH_PATH, "w", encoding="utf-8") as f:
        json.dump(auth, f, ensure_ascii=False, indent=2)
    return {"status": "ok"}

# ============ CONTACTS ENDPOINTS ============
@app.get("/api/contacts")
async def list_contacts(q: str = "", qualite: str = "", user=Depends(require_auth)):
    data = load_db()
    contacts = data["contacts"]
    # Members: only see other members and referents (not donors, journalists, etc.)
    if is_member(user):
        contacts = [c for c in contacts if c.get("qualite", "").lower() in ("membre asso", "referent", "benevole")]
    if q:
        ql = q.lower()
        contacts = [c for c in contacts if ql in (c.get("prenom","") + " " + c.get("nom","") + " " + c.get("email","") + " " + c.get("telephone","") + " " + c.get("notes","") + " " + c.get("tags","") + " " + c.get("qualite","")).lower()]
    if qualite:
        contacts = [c for c in contacts if c.get("qualite","").lower() == qualite.lower()]
    return contacts

@app.get("/api/contacts/{contact_id}")
async def get_contact(contact_id: str, user=Depends(require_auth)):
    data = load_db()
    for c in data["contacts"]:
        if c["id"] == contact_id:
            # Members: cannot view contacts outside member/referent/benevole
            if is_member(user):
                if c.get("qualite", "").lower() not in ("membre asso", "referent", "benevole"):
                    raise HTTPException(status_code=403, detail="Acces refuse")
            return c
    raise HTTPException(status_code=404, detail="Contact non trouve")

@app.post("/api/contacts")
async def create_contact(req: ContactCreate, user=Depends(require_referent)):
    data = load_db()
    contact = {
        "id": gen_id(),
        "prenom": req.prenom.strip(),
        "nom": req.nom.strip().upper(),
        "qualite": req.qualite.strip(),
        "telephone": normalize_phone(req.telephone),
        "email": req.email.strip().lower(),
        "notes": req.notes.strip(),
        "tags": req.tags.strip(),
        "historique": [],
        "cree_par": user["username"],
        "cree_le": now_iso(),
        "modifie_par": "",
        "modifie_le": ""
    }
    add_history(contact, user, "creation", f"Contact cree par {user['username']}")
    data["contacts"].append(contact)
    save_db(data)
    backup_db()
    return {"status": "ok", "contact": contact}

@app.put("/api/contacts/{contact_id}")
async def update_contact(contact_id: str, req: ContactUpdate, user=Depends(require_referent)):
    data = load_db()
    for c in data["contacts"]:
        if c["id"] == contact_id:
            changes = []
            if c["prenom"] != req.prenom:
                changes.append(f"prenom: '{c['prenom']}' -> '{req.prenom}'")
                c["prenom"] = req.prenom.strip()
            if c["nom"].upper() != req.nom.strip().upper():
                changes.append(f"nom: '{c['nom']}' -> '{req.nom}'")
                c["nom"] = req.nom.strip().upper()
            if c["qualite"] != req.qualite:
                changes.append(f"qualite: '{c['qualite']}' -> '{req.qualite}'")
                c["qualite"] = req.qualite.strip()
            old_tel = c["telephone"]
            new_tel = normalize_phone(req.telephone)
            if old_tel != new_tel:
                changes.append(f"telephone: '{old_tel}' -> '{new_tel}'")
                c["telephone"] = new_tel
            if c["email"] != req.email.lower():
                changes.append(f"email: '{c['email']}' -> '{req.email}'")
                c["email"] = req.email.strip().lower()
            if c["notes"] != req.notes:
                changes.append(f"notes modifiees")
                c["notes"] = req.notes.strip()
            if c.get("tags", "") != req.tags:
                changes.append(f"tags: '{c.get('tags', '')}' -> '{req.tags}'")
                c["tags"] = req.tags.strip()
            if changes:
                add_history(c, user, "modification", " | ".join(changes))
                save_db(data)
                backup_db()
            return {"status": "ok", "contact": c}
    raise HTTPException(status_code=404, detail="Contact non trouve")

@app.delete("/api/contacts/{contact_id}")
async def delete_contact(contact_id: str, user=Depends(require_referent)):
    data = load_db()
    before = len(data["contacts"])
    contact = None
    for c in data["contacts"]:
        if c["id"] == contact_id:
            contact = c
            break
    if not contact:
        raise HTTPException(status_code=404, detail="Contact non trouve")
    data["contacts"] = [c for c in data["contacts"] if c["id"] != contact_id]
    save_db(data)
    backup_db()
    return {"status": "ok", "deleted": contact_id}

@app.post("/api/contacts/{contact_id}/historique")
async def add_historique(contact_id: str, req: HistoriqueEntry, user=Depends(require_referent)):
    data = load_db()
    for c in data["contacts"]:
        if c["id"] == contact_id:
            add_history(c, user, req.action, req.details)
            save_db(data)
            backup_db()
            return {"status": "ok", "contact": c}
    raise HTTPException(status_code=404, detail="Contact non trouve")

@app.get("/api/contacts/{contact_id}/historique")
async def get_historique(contact_id: str, user=Depends(require_referent)):
    data = load_db()
    for c in data["contacts"]:
        if c["id"] == contact_id:
            return c.get("historique", [])
    raise HTTPException(status_code=404, detail="Contact non trouve")

# ============ EVENEMENTS ENDPOINTS ============

def _format_date_fr(date_str):
    """Convertit YYYY-MM-DD en date francaise lisible, ex: mercredi 15 juillet 2026."""
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        jours = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]
        mois = ["janvier", "fevrier", "mars", "avril", "mai", "juin",
                "juillet", "aout", "septembre", "octobre", "novembre", "decembre"]
        return f"{jours[dt.weekday()]} {dt.day} {mois[dt.month - 1]} {dt.year}"
    except Exception:
        return date_str

def _send_event_notification(ev, data, user):
    """
    Envoie un email automatique aux participants d'un evenement qui ont un email.
    Retourne un dict {sent_to, count} si un email a ete envoye, None sinon.
    Si SMTP n'est pas configure ou aucun participant n'a d'email, retourne None (silencieux).
    """
    # Verifier que SMTP est configure
    smtp = load_smtp()
    if not smtp.get("password"):
        return None

    # Recuperer les contacts participants
    participant_ids = ev.get("participants", [])
    if not participant_ids:
        return None

    contacts_by_id = {c["id"]: c for c in data["contacts"]}
    participant_contacts = []
    for pid in participant_ids:
        c = contacts_by_id.get(pid)
        if c and c.get("email") and c["email"].strip():
            participant_contacts.append(c)

    if not participant_contacts:
        return None

    # Construire la liste des noms des participants (tous, meme sans email)
    all_names = []
    for pid in participant_ids:
        c = contacts_by_id.get(pid)
        if c:
            all_names.append(f"{c.get('prenom', '')} {c.get('nom', '')}".strip())
        else:
            all_names.append(pid)
    participants_str = ", ".join(all_names)

    # Construire le sujet et le corps
    sujet = f"Evenement : {ev['titre']}"

    lignes = []
    lignes.append(f"Bonjour,")
    lignes.append("")
    lignes.append(f"Un evenement a ete cree dans le CRM de l'association Les Ami(e)s de Romy :")
    lignes.append("")
    lignes.append(f"Titre : {ev['titre']}")
    date_fr = _format_date_fr(ev.get("date", ""))
    if ev.get("heure"):
        lignes.append(f"Date : {date_fr} a {ev['heure']}")
    else:
        lignes.append(f"Date : {date_fr}")
    if ev.get("lieu"):
        lignes.append(f"Lieu : {ev['lieu']}")
    if ev.get("description"):
        lignes.append(f"Description : {ev['description']}")
    lignes.append(f"Participants : {participants_str}")
    lignes.append(f"Cree par : {user['username']}")
    lignes.append("")
    lignes.append("Cordialement,")
    lignes.append("L'equipe des Ami(e)s de Romy")

    body = "\n".join(lignes)

    # Recuperer les emails des participants qui en ont un
    recipient_emails = [c["email"].strip() for c in participant_contacts]

    try:
        send_email_smtp(recipient_emails, sujet, body)
    except Exception:
        # Si l'envoi echoue, on ne bloque pas la creation de l'evenement
        return None

    # Ajouter une entree d'historique a chaque participant notifie
    for c in participant_contacts:
        add_history(c, user, "email", f"Notification evenement: {ev['titre']}")

    return {"sent_to": recipient_emails, "count": len(recipient_emails)}

@app.get("/api/evenements")
async def list_evenements(user=Depends(require_auth)):
    data = load_db()
    return data.get("evenements", [])

@app.post("/api/evenements")
async def create_evenement(req: EvenementCreate, user=Depends(require_referent)):
    data = load_db()
    ev = {
        "id": f"evt-{secrets.token_hex(8)}",
        "titre": req.titre,
        "date": req.date,
        "heure": req.heure,
        "lieu": req.lieu,
        "description": req.description,
        "participants": req.participants,
        "presence": {},
        "rappel_envoye": False,
        "cree_par": user["username"],
        "cree_le": now_iso(),
        "historique": [{"date": now_iso(), "user": user["username"], "action": "creation"}]
    }
    data["evenements"].append(ev)
    save_db(data)
    backup_db()

    # --- Envoi email automatique aux participants qui ont un email ---
    email_info = _send_event_notification(ev, data, user)
    if email_info:
        ev["email_sent"] = email_info
        save_db(data)

    return {"status": "ok", "evenement": ev}

@app.put("/api/evenements/{evt_id}")
async def update_evenement(evt_id: str, req: EvenementUpdate, user=Depends(require_referent)):
    data = load_db()
    for ev in data["evenements"]:
        if ev["id"] == evt_id:
            changes = []
            if req.titre is not None and ev["titre"] != req.titre:
                changes.append(f"titre modifie")
                ev["titre"] = req.titre
            if req.date is not None and ev["date"] != req.date:
                changes.append(f"date: '{ev['date']}' -> '{req.date}'")
                ev["date"] = req.date
            if req.heure is not None and ev.get("heure", "") != req.heure:
                changes.append(f"heure: '{ev.get('heure', '')}' -> '{req.heure}'")
                ev["heure"] = req.heure
            if req.lieu is not None and ev["lieu"] != req.lieu:
                changes.append(f"lieu modifie")
                ev["lieu"] = req.lieu
            if req.description is not None and ev["description"] != req.description:
                changes.append("description modifiee")
                ev["description"] = req.description
            if req.participants is not None:
                old = set(ev.get("participants", []))
                new = set(req.participants)
                added = new - old
                removed = old - new
                if added:
                    changes.append(f"participants ajoutes: {', '.join(added)}")
                if removed:
                    changes.append(f"participants retires: {', '.join(removed)}")
                ev["participants"] = req.participants
            if req.presence is not None:
                ev["presence"] = req.presence
                changes.append("presence mise a jour")
            if changes:
                ev.setdefault("historique", []).append({"date": now_iso(), "user": user["username"], "action": "modification", "details": " | ".join(changes)})
            save_db(data)
            backup_db()
            return {"status": "ok", "evenement": ev}
    raise HTTPException(status_code=404, detail="Evenement non trouve")

@app.delete("/api/evenements/{evt_id}")
async def delete_evenement(evt_id: str, user=Depends(require_referent)):
    data = load_db()
    data["evenements"] = [e for e in data["evenements"] if e["id"] != evt_id]
    save_db(data)
    backup_db()
    return {"status": "ok"}

# ============ PRESENCE (membre self-registration) ============
@app.post("/api/evenements/{evt_id}/presence")
async def set_self_presence(evt_id: str, req: PresenceSelf, user=Depends(require_auth)):
    """Any logged-in user (including members) can set their own presence."""
    data = load_db()
    for ev in data["evenements"]:
        if ev["id"] == evt_id:
            presence = ev.get("presence", {})
            presence[req.contact_id] = req.presence
            ev["presence"] = presence
            ev.setdefault("historique", []).append({
                "date": now_iso(),
                "user": user["username"],
                "action": "presence_auto",
                "details": f"Contact {req.contact_id}: {req.presence}"
            })
            save_db(data)
            backup_db()
            return {"status": "ok", "evenement": ev}
    raise HTTPException(status_code=404, detail="Evenement non trouve")

# ============ COTISATIONS ENDPOINTS ============
@app.get("/api/cotisations")
async def list_cotisations(annee: str = "", contact_id: str = "", user=Depends(require_referent)):
    data = load_db()
    cotisations = data.get("cotisations", [])
    contact_by_id = {c["id"]: c for c in data["contacts"]}
    if annee:
        cotisations = [c for c in cotisations if c.get("annee") == annee]
    if contact_id:
        cotisations = [c for c in cotisations if c.get("contact_id") == contact_id]
    # Enrichir avec le nom du contact
    for cot in cotisations:
        c = contact_by_id.get(cot.get("contact_id"), {})
        cot["contact_nom"] = f"{c.get('prenom','')} {c.get('nom','')}".strip()
        cot["contact_email"] = c.get("email", "")
    return cotisations

@app.post("/api/cotisations")
async def create_cotisation(req: CotisationCreate, user=Depends(require_referent)):
    data = load_db()
    cot = {
        "id": f"cot-{secrets.token_hex(8)}",
        "contact_id": req.contact_id,
        "annee": req.annee,
        "montant": req.montant,
        "date_paiement": req.date_paiement,
        "mode_paiement": req.mode_paiement,
        "statut": req.statut,
        "notes": req.notes,
        "cree_par": user["username"],
        "cree_le": now_iso()
    }
    data.setdefault("cotisations", []).append(cot)
    for c in data["contacts"]:
        if c["id"] == req.contact_id:
            add_history(c, user, "cotisation", f"Annee {req.annee} | {req.statut} | {req.montant} EUR")
            break
    save_db(data)
    backup_db()
    return {"status": "ok", "cotisation": cot}

@app.put("/api/cotisations/{cot_id}")
async def update_cotisation(cot_id: str, req: CotisationUpdate, user=Depends(require_referent)):
    data = load_db()
    for cot in data.get("cotisations", []):
        if cot["id"] == cot_id:
            if req.montant is not None:
                cot["montant"] = req.montant
            if req.date_paiement is not None:
                cot["date_paiement"] = req.date_paiement
            if req.mode_paiement is not None:
                cot["mode_paiement"] = req.mode_paiement
            if req.statut is not None:
                cot["statut"] = req.statut
            if req.notes is not None:
                cot["notes"] = req.notes
            save_db(data)
            backup_db()
            return {"status": "ok", "cotisation": cot}
    raise HTTPException(status_code=404, detail="Cotisation non trouvee")

@app.delete("/api/cotisations/{cot_id}")
async def delete_cotisation(cot_id: str, user=Depends(require_referent)):
    data = load_db()
    data["cotisations"] = [c for c in data.get("cotisations", []) if c["id"] != cot_id]
    save_db(data)
    backup_db()
    return {"status": "ok"}

# ============ RAPPEL EMAIL AUTOMATIQUE (J-2) ============
def _send_event_reminder(ev, data):
    smtp = load_smtp()
    if not smtp.get("password"):
        return False
    participant_ids = ev.get("participants", [])
    if not participant_ids:
        return False
    contacts_by_id = {c["id"]: c for c in data["contacts"]}
    recipient_emails = []
    for pid in participant_ids:
        c = contacts_by_id.get(pid)
        if c and c.get("email") and c["email"].strip():
            recipient_emails.append(c["email"].strip())
    if not recipient_emails:
        return False
    sujet = f"Rappel : {ev['titre']}"
    date_fr = _format_date_fr(ev.get("date", ""))
    lignes = [
        "Bonjour,",
        "",
        "Ceci est un rappel pour l evenement suivant qui aura lieu prochainement :",
        "",
        f"Titre : {ev['titre']}",
        f"Date : {date_fr}" + (f" a {ev['heure']}" if ev.get("heure") else ""),
        f"Lieu : {ev.get('lieu', 'non precise')}" if ev.get("lieu") else "",
        "",
        "Au plaisir de vous y retrouver,",
        "L equipe des Ami(e)s de Romy"
    ]
    body = "\n".join(lignes)
    try:
        send_email_smtp(recipient_emails, sujet, body)
        return True
    except Exception:
        return False

def _reminder_check_loop():
    """Thread de fond: scrute toutes les 30 min les evenements a J-2."""
    while True:
        time.sleep(1800)
        try:
            data = load_db()
            smtp = load_smtp()
            if not smtp.get("password"):
                continue
            today = datetime.now().date()
            for ev in data.get("evenements", []):
                if ev.get("rappel_envoye"):
                    continue
                if not ev.get("date"):
                    continue
                try:
                    ev_date = datetime.strptime(ev["date"], "%Y-%m-%d").date()
                except Exception:
                    continue
                delta = (ev_date - today).days
                if delta == 2:
                    sent = _send_event_reminder(ev, data)
                    if sent:
                        ev["rappel_envoye"] = True
                        save_db(data)
                        print(f"[RAPPEL] Rappel envoye pour: {ev['titre']}")
        except Exception as e:
            print(f"[RAPPEL] Erreur: {e}")

# ============ DOCUMENTS ENDPOINTS ============
@app.get("/api/documents")
async def list_documents(user=Depends(require_referent)):
    data = load_db()
    return data.get("documents", [])

@app.post("/api/documents")
async def upload_document(request: Request, user=Depends(require_referent)):
    form = await request.form()
    nom = form.get("nom", "")
    type_doc = form.get("type_doc", "")
    description = form.get("description", "")
    file = form.get("file")
    
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="Fichier requis")
    
    # restriction des extensions autorisees
    ALLOWED_EXTENSIONS = {".pdf", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".odt", ".ods", ".odp", ".rtf", ".zip"}
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Type de fichier non autorise: {ext}")
    
    # limite de taille: 20 Mo
    MAX_FILE_SIZE = 20 * 1024 * 1024
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="Fichier trop volumineux (max 20 Mo)")
    
    safe_name = re.sub(r'[^\w\.-]', '_', file.filename)
    # eviter path traversal
    safe_name = safe_name.replace("..", "").replace("/", "").replace("\\", "")
    filepath = DOCS_DIR / safe_name
    with open(filepath, "wb") as f:
        f.write(content)
    
    data = load_db()
    doc = {
        "id": f"doc-{secrets.token_hex(8)}",
        "nom": nom or safe_name,
        "type_doc": type_doc,
        "description": description,
        "filename": safe_name,
        "filepath": str(filepath),
        "taille": len(content),
        "cree_par": user["username"],
        "cree_le": now_iso()
    }
    data.setdefault("documents", []).append(doc)
    save_db(data)
    return {"status": "ok", "document": doc}

@app.get("/api/documents/{doc_id}")
async def download_document(doc_id: str, user=Depends(require_referent)):
    data = load_db()
    for d in data.get("documents", []):
        if d["id"] == doc_id:
            if not os.path.exists(d["filepath"]):
                raise HTTPException(status_code=404, detail="Fichier introuvable")
            return FileResponse(d["filepath"], filename=d["filename"])
    raise HTTPException(status_code=404, detail="Document non trouve")

@app.delete("/api/documents/{doc_id}")
async def delete_document(doc_id: str, user=Depends(require_referent)):
    data = load_db()
    for d in data.get("documents", []):
        if d["id"] == doc_id:
            if os.path.exists(d["filepath"]):
                os.unlink(d["filepath"])
            data["documents"] = [x for x in data["documents"] if x["id"] != doc_id]
            save_db(data)
            return {"status": "ok"}
    raise HTTPException(status_code=404, detail="Document non trouve")

# ============ EMAILING ENDPOINTS ============
@app.post("/api/email/send")
async def send_email(req: EmailSend, user=Depends(require_referent)):
    data = load_db()
    recipients = list(req.recipients)
    
    # Collect emails from contact_ids
    for cid in req.contact_ids:
        for c in data["contacts"]:
            if c["id"] == cid and c.get("email"):
                recipients.append(c["email"])
    
    recipients = list(set(r for r in recipients if r))
    if not recipients:
        raise HTTPException(status_code=400, detail="Aucun destinataire valide")
    
    try:
        send_email_smtp(recipients, req.subject, req.body, html=req.html)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur envoi email: {str(e)}")
    
    # Log email in each contact's history
    for cid in req.contact_ids:
        for c in data["contacts"]:
            if c["id"] == cid:
                add_history(c, user, "email", f"Sujet: {req.subject} | A: {', '.join(recipients)}")
    save_db(data)
    
    return {"status": "ok", "sent_to": recipients, "count": len(recipients)}

@app.get("/api/email/templates")
async def get_templates(user=Depends(require_referent)):
    return {
        "newsletter": {
            "subject": "Newsletter - Les Ami(e)s de Romy",
            "body": "Bonjour,\n\nVoici les dernieres nouvelles de l'association Les Ami(e)s de Romy.\n\n[Contenu a personnaliser]\n\nCordialement,\nL'equipe des Ami(e)s de Romy"
        },
        "relance": {
            "subject": "Relance - Les Ami(e)s de Romy",
            "body": "Bonjour,\n\nNous vous contactons dans le cadre de l'association Les Ami(e)s de Romy.\n\n[Contenu a personnaliser]\n\nCordialement,\nL'equipe des Ami(e)s de Romy"
        },
        "invitation": {
            "subject": "Invitation evenement - Les Ami(e)s de Romy",
            "body": "Bonjour,\n\nVous etes invite(e) a notre prochain evenement.\n\nDate: [A completer]\nLieu: [A completer]\n\n[Description]\n\nAu plaisir de vous y retrouver,\nL'equipe des Ami(e)s de Romy"
        },
        "newsletter_html": {
            "subject": "Newsletter - Les Ami(e)s de Romy",
            "body": "<div style=\"font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#f3e0f5;padding:20px;border-radius:12px\"><div style=\"text-align:center;padding:20px 0\"><span style=\"font-size:2rem\">&hearts;</span><h1 style=\"color:#d03ec6;margin:0\">Les Ami(e)s de Romy</h1></div><div style=\"background:#fff;padding:20px;border-radius:8px\"><p>Bonjour,</p><p>Voici les dernieres nouvelles de l association.</p><p>[Contenu a personnaliser]</p><p style=\"color:#999;font-size:.85rem\">L equipe des Ami(e)s de Romy</p></div></div>",
            "html": True
        }
    }

@app.get("/api/email/preview-contacts")
async def preview_email_contacts(contact_ids: str = "", user=Depends(require_referent)):
    """Returns emails for given contact IDs"""
    data = load_db()
    ids = [x.strip() for x in contact_ids.split(",") if x.strip()]
    emails = []
    for c in data["contacts"]:
        if c["id"] in ids and c.get("email"):
            emails.append({"id": c["id"], "nom": f"{c['prenom']} {c['nom']}", "email": c["email"]})
    return emails

# ============ STATS ============
@app.get("/api/stats")
async def get_stats(user=Depends(require_referent)):
    data = load_db()
    contacts = data["contacts"]
    qualites = {}
    for c in contacts:
        q = c.get("qualite", "non specifie") or "non specifie"
        qualites[q] = qualites.get(q, 0) + 1
    return {
        "total_contacts": len(contacts),
        "total_evenements": len(data.get("evenements", [])),
        "total_documents": len(data.get("documents", [])),
        "total_cotisations": len(data.get("cotisations", [])),
        "par_qualite": qualites,
        "avec_email": sum(1 for c in contacts if c.get("email")),
        "sans_email": sum(1 for c in contacts if not c.get("email")),
        "avec_telephone": sum(1 for c in contacts if c.get("telephone")),
        "cotisations_payees": sum(1 for c in data.get("cotisations", []) if c.get("statut") == "paye"),
        "cotisations_impayees": sum(1 for c in data.get("cotisations", []) if c.get("statut") != "paye"),
        "montant_cotisations": sum(c.get("montant", 0) for c in data.get("cotisations", []) if c.get("statut") == "paye"),
        "total_dons": len(data.get("dons", [])),
        "montant_dons": sum(d.get("montant", 0) for d in data.get("dons", [])),
        "total_taches": len(data.get("taches", [])),
        "taches_a_faire": sum(1 for t in data.get("taches", []) if t.get("statut") == "a_faire"),
        "taches_terminees": sum(1 for t in data.get("taches", []) if t.get("statut") == "terminee"),
    }

# ============ STATS AVANCEES ============
@app.get("/api/stats/advanced")
async def get_stats_advanced(user=Depends(require_referent)):
    data = load_db()
    contacts = data["contacts"]
    events = data.get("evenements", [])
    cots = data.get("cotisations", [])

    # Cotisations par annee
    cotisations_par_annee = {}
    for c in cots:
        annee = c.get("annee", "N/A")
        if annee not in cotisations_par_annee:
            cotisations_par_annee[annee] = {"total": 0, "paye": 0, "impaye": 0, "montant": 0}
        cotisations_par_annee[annee]["total"] += 1
        if c.get("statut") == "paye":
            cotisations_par_annee[annee]["paye"] += 1
            cotisations_par_annee[annee]["montant"] += c.get("montant", 0)
        else:
            cotisations_par_annee[annee]["impaye"] += 1

    # Participation aux evenements
    participation = []
    contact_by_id = {c["id"]: c for c in contacts}
    for ev in events:
        parts = ev.get("participants", [])
        presence = ev.get("presence", {})
        presents = sum(1 for v in presence.values() if v == "present")
        absents = sum(1 for v in presence.values() if v == "absent")
        excuses = sum(1 for v in presence.values() if v == "excuse")
        participation.append({
            "titre": ev.get("titre", ""),
            "date": ev.get("date", ""),
            "inscrits": len(parts),
            "presents": presents,
            "absents": absents,
            "excuses": excuses,
            "taux_presence": round(presents / len(parts) * 100, 1) if parts else 0
        })

    # Repartition par tags
    tags_count = {}
    for c in contacts:
        for tag in c.get("tags", "").split(","):
            tag = tag.strip()
            if tag:
                tags_count[tag] = tags_count.get(tag, 0) + 1

    # Contacts sans cotisation (annee en cours)
    current_year = str(datetime.now().year)
    contacts_avec_cot_annee = set()
    for c in cots:
        if c.get("annee") == current_year and c.get("statut") == "paye":
            contacts_avec_cot_annee.add(c.get("contact_id"))
    contacts_sans_cot = [c["id"] for c in contacts if c["id"] not in contacts_avec_cot_annee]

    return {
        "cotisations_par_annee": cotisations_par_annee,
        "participation_evenements": participation,
        "tags_count": tags_count,
        "contacts_sans_cotisation": len(contacts_sans_cot),
        "total_cotisations": len(cots),
        "total_evenements": len(events),
    }

# ============ CALENDRIER MENSUEL ============
@app.get("/api/evenements/calendrier")
async def get_calendrier(mois: int = 0, user=Depends(require_auth)):
    """Retourne les evenements du mois specifie (0=mois courant, 1=mois prochain, -1=mois precedent)."""
    from datetime import timedelta
    data = load_db()
    today = datetime.now().date()
    # Calculer le mois cible
    if mois == 0:
        target = today.replace(day=1)
    elif mois > 0:
        target = today.replace(day=1)
        for _ in range(mois):
            if target.month == 12:
                target = target.replace(year=target.year + 1, month=1)
            else:
                target = target.replace(month=target.month + 1)
    else:
        target = today.replace(day=1)
        for _ in range(abs(mois)):
            if target.month == 1:
                target = target.replace(year=target.year - 1, month=12)
            else:
                target = target.replace(month=target.month - 1)

    # Filtrer les evenements du mois
    events_mois = []
    contact_by_id = {c["id"]: c for c in data["contacts"]}
    for ev in data.get("evenements", []):
        try:
            ev_date = datetime.strptime(ev.get("date", ""), "%Y-%m-%d").date()
        except Exception:
            continue
        if ev_date.year == target.year and ev_date.month == target.month:
            # Resoudre les noms des participants
            parts_noms = []
            for pid in ev.get("participants", []):
                c = contact_by_id.get(pid, {})
                parts_noms.append(f"{c.get('prenom', '')} {c.get('nom', '')}".strip())
            events_mois.append({
                "id": ev["id"],
                "titre": ev.get("titre", ""),
                "date": ev.get("date", ""),
                "heure": ev.get("heure", ""),
                "lieu": ev.get("lieu", ""),
                "description": ev.get("description", ""),
                "participants": parts_noms,
                "jour": ev_date.day
            })

    # Informations sur le mois
    if target.month == 12:
        next_month = target.replace(year=target.year + 1, month=1)
    else:
        next_month = target.replace(month=target.month + 1)
    prev_month = target.replace(day=1) - timedelta(days=1)
    prev_month = prev_month.replace(day=1)

    return {
        "mois_cible": target.strftime("%Y-%m"),
        "mois_label": target.strftime("%B %Y"),
        "mois_label_fr": _format_date_fr(target.strftime("%Y-%m-01")).split()[1] + " " + str(target.year),
        "nb_jours": (next_month - target).days,
        "events": events_mois,
        "prev_mois": prev_month.strftime("%Y-%m"),
        "next_mois": next_month.strftime("%Y-%m"),
    }

# ============ TACHES ENDPOINTS ============
@app.get("/api/taches")
async def list_taches(statut: str = "", user=Depends(require_referent)):
    data = load_db()
    taches = data.get("taches", [])
    if statut:
        taches = [t for t in taches if t.get("statut") == statut]
    return taches

@app.post("/api/taches")
async def create_tache(req: TacheCreate, user=Depends(require_referent)):
    data = load_db()
    tache = {
        "id": f"tache-{secrets.token_hex(8)}",
        "titre": req.titre,
        "description": req.description,
        "assigne_a": req.assigne_a,
        "echeance": req.echeance,
        "priorite": req.priorite,
        "statut": "a_faire",
        "cree_par": user["username"],
        "cree_le": now_iso()
    }
    data.setdefault("taches", []).append(tache)
    save_db(data)
    backup_db()
    return {"status": "ok", "tache": tache}

@app.put("/api/taches/{tache_id}")
async def update_tache(tache_id: str, req: TacheUpdate, user=Depends(require_referent)):
    data = load_db()
    for t in data.get("taches", []):
        if t["id"] == tache_id:
            if req.titre is not None: t["titre"] = req.titre
            if req.description is not None: t["description"] = req.description
            if req.assigne_a is not None: t["assigne_a"] = req.assigne_a
            if req.echeance is not None: t["echeance"] = req.echeance
            if req.priorite is not None: t["priorite"] = req.priorite
            if req.statut is not None: t["statut"] = req.statut
            save_db(data)
            backup_db()
            return {"status": "ok", "tache": t}
    raise HTTPException(status_code=404, detail="Tache non trouvee")

@app.delete("/api/taches/{tache_id}")
async def delete_tache(tache_id: str, user=Depends(require_referent)):
    data = load_db()
    data["taches"] = [t for t in data.get("taches", []) if t["id"] != tache_id]
    save_db(data)
    backup_db()
    return {"status": "ok"}

# ============ DONS / SPONSORS ENDPOINTS ============
@app.get("/api/dons")
async def list_dons(type_don: str = "", user=Depends(require_referent)):
    data = load_db()
    dons = data.get("dons", [])
    if type_don:
        dons = [d for d in dons if d.get("type_don") == type_don]
    return dons

@app.post("/api/dons")
async def create_don(req: DonCreate, user=Depends(require_referent)):
    data = load_db()
    don = {
        "id": f"don-{secrets.token_hex(8)}",
        "contact_id": req.contact_id,
        "nom": req.nom,
        "montant": req.montant,
        "date": req.date,
        "mode_paiement": req.mode_paiement,
        "type_don": req.type_don,
        "notes": req.notes,
        "cree_par": user["username"],
        "cree_le": now_iso()
    }
    data.setdefault("dons", []).append(don)
    save_db(data)
    backup_db()
    return {"status": "ok", "don": don}

@app.delete("/api/dons/{don_id}")
async def delete_don(don_id: str, user=Depends(require_referent)):
    data = load_db()
    data["dons"] = [d for d in data.get("dons", []) if d["id"] != don_id]
    save_db(data)
    backup_db()
    return {"status": "ok"}

# ============ PHOTOS EVENEMENTS ============
@app.post("/api/evenements/{evt_id}/photos")
async def upload_event_photo(evt_id: str, request: Request, user=Depends(require_referent)):
    form = await request.form()
    file = form.get("file")
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="Fichier requis")
    ALLOWED_IMG = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_IMG:
        raise HTTPException(status_code=400, detail=f"Type non autorise: {ext}")
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Max 10 Mo")
    safe_name = re.sub(r'[^\w\.-]', '_', file.filename)
    safe_name = safe_name.replace("..", "").replace("/", "").replace("\\", "")
    # Prefix avec evt_id pour organiser
    photo_filename = f"{evt_id}_{safe_name}"
    filepath = DOCS_DIR / "event_photos" / photo_filename
    filepath.parent.mkdir(exist_ok=True)
    with open(filepath, "wb") as f:
        f.write(content)
    data = load_db()
    for ev in data.get("evenements", []):
        if ev["id"] == evt_id:
            ev.setdefault("photos", []).append({
                "filename": photo_filename,
                "filepath": str(filepath),
                "cree_par": user["username"],
                "cree_le": now_iso()
            })
            save_db(data)
            backup_db()
            return {"status": "ok", "photo": photo_filename}
    raise HTTPException(status_code=404, detail="Evenement non trouve")

@app.get("/api/evenements/{evt_id}/photos")
async def list_event_photos(evt_id: str, user=Depends(require_auth)):
    data = load_db()
    for ev in data.get("evenements", []):
        if ev["id"] == evt_id:
            return ev.get("photos", [])
    raise HTTPException(status_code=404, detail="Evenement non trouve")

@app.delete("/api/evenements/{evt_id}/photos/{photo_idx}")
async def delete_event_photo(evt_id: str, photo_idx: int, user=Depends(require_referent)):
    data = load_db()
    for ev in data.get("evenements", []):
        if ev["id"] == evt_id:
            photos = ev.get("photos", [])
            if 0 <= photo_idx < len(photos):
                if os.path.exists(photos[photo_idx].get("filepath", "")):
                    os.unlink(photos[photo_idx]["filepath"])
                photos.pop(photo_idx)
                save_db(data)
                backup_db()
                return {"status": "ok"}
    raise HTTPException(status_code=404, detail="Photo non trouvee")

# ============ EXPORT EXCEL ============
@app.get("/api/export/contacts-excel")
async def export_contacts_excel(user=Depends(require_referent)):
    import openpyxl
    import tempfile
    data = load_db()
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Contacts"
    headers = ["ID", "Prenom", "Nom", "Qualite", "Telephone", "Email", "Tags", "Notes"]
    ws.append(headers)
    for c in data["contacts"]:
        ws.append([c.get("id",""), c.get("prenom",""), c.get("nom",""), c.get("qualite",""),
                    c.get("telephone",""), c.get("email",""), c.get("tags",""), c.get("notes","")])
    # Cotisations sheet
    ws2 = wb.create_sheet("Cotisations")
    ws2.append(["Contact", "Annee", "Montant", "Statut", "Mode", "Date paiement"])
    contact_by_id = {c["id"]: c for c in data["contacts"]}
    for cot in data.get("cotisations", []):
        c = contact_by_id.get(cot.get("contact_id"), {})
        ws2.append([f"{c.get('prenom','')} {c.get('nom','')}", cot.get("annee",""), cot.get("montant",0),
                    cot.get("statut",""), cot.get("mode_paiement",""), cot.get("date_paiement","")])
    # Evenements sheet
    ws3 = wb.create_sheet("Evenements")
    ws3.append(["Titre", "Date", "Heure", "Lieu", "Description", "Participants", "Cree par"])
    for ev in data.get("evenements", []):
        parts = []
        for pid in ev.get("participants", []):
            c = contact_by_id.get(pid, {})
            parts.append(f"{c.get('prenom','')} {c.get('nom','')}".strip())
        ws3.append([ev.get("titre",""), ev.get("date",""), ev.get("heure",""),
                    ev.get("lieu",""), ev.get("description",""), ", ".join(parts), ev.get("cree_par","")])
    tmp_path = tempfile.mktemp(suffix=".xlsx")
    wb.save(tmp_path)
    return FileResponse(tmp_path, filename="export_contacts_cotisations.xlsx")

# ============ EXPORT ICS ============
@app.get("/api/export/evenements-ics")
async def export_evenements_ics(user=Depends(require_auth)):
    import tempfile
    data = load_db()
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//CRM Romy//FR", "CALSCALE:GREGORIAN"]
    for ev in data.get("evenements", []):
        lines.append("BEGIN:VEVENT")
        lines.append(f"UID:{ev['id']}@crm-romy")
        date = ev.get("date", "")
        heure = ev.get("heure", "")
        if date:
            if heure:
                dt_start = f"{date.replace('-','')}T{heure.replace(':','')}00"
                lines.append(f"DTSTART:{dt_start}")
                lines.append(f"DTEND:{date.replace('-','')}T{heure.replace(':','')}00")
            else:
                lines.append(f"DTSTART;VALUE=DATE:{date.replace('-','')}")
        lines.append(f"SUMMARY:{ev.get('titre','')}")
        if ev.get("lieu"):
            lines.append(f"LOCATION:{ev['lieu']}")
        if ev.get("description"):
            lines.append(f"DESCRIPTION:{ev['description']}")
        lines.append("END:VEVENT")
    lines.append("END:VCALENDAR")
    ics_content = (chr(13) + chr(10)).join(lines)
    tmp_path = tempfile.mktemp(suffix=".ics")
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(ics_content)
    return FileResponse(tmp_path, filename="evenements_romy.ics", media_type="text/calendar")

# ============ FEEDBACK (BUG / SUGGESTION) ============
@app.post("/api/feedback")
async def create_feedback(req: FeedbackCreate, user=Depends(require_auth)):
    data = load_db()
    fb = {
        "id": f"fb-{secrets.token_hex(8)}",
        "type": req.type,
        "message": req.message,
        "page": req.page,
        "user": user["username"],
        "date": now_iso(),
        "statut": "ouvert"
    }
    data.setdefault("feedbacks", []).append(fb)
    save_db(data)
    backup_db()
    # Envoyer un email a Vincent
    smtp = load_smtp()
    if smtp.get("password"):
        sujet = f"[CRM Romy] {req.type.upper()} - par {user['username']}"
        body = f"Type: {req.type}\nUtilisateur: {user['username']}\nPage: {req.page or 'non precisee'}\n\nMessage:\n{req.message}"
        try:
            send_email_smtp(["vincentminvielle@gmail.com"], sujet, body)
        except Exception:
            pass  # Ne pas bloquer si l email echoue
    return {"status": "ok", "feedback": fb}

@app.get("/api/feedback")
async def list_feedback(user=Depends(require_referent)):
    data = load_db()
    return data.get("feedbacks", [])

@app.put("/api/feedback/{fb_id}")
async def update_feedback(fb_id: str, req: dict, user=Depends(require_referent)):
    data = load_db()
    for fb in data.get("feedbacks", []):
        if fb["id"] == fb_id:
            if "statut" in req:
                fb["statut"] = req["statut"]
            save_db(data)
            backup_db()
            return {"status": "ok", "feedback": fb}
    raise HTTPException(status_code=404, detail="Feedback non trouve")

@app.delete("/api/feedback/{fb_id}")
async def delete_feedback(fb_id: str, user=Depends(require_referent)):
    data = load_db()
    data["feedbacks"] = [f for f in data.get("feedbacks", []) if f["id"] != fb_id]
    save_db(data)
    backup_db()
    return {"status": "ok"}

# ============ STATIC FILES + SPA ============
@app.get("/")
async def index():
    index_path = BASE_DIR / "static" / "index.html"
    with open(index_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.get("/favicon.ico")
async def favicon():
    return Response(b"", media_type="image/x-icon")

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# ============ IMPORT EXCEL ============
@app.post("/api/import/excel")
async def import_excel(request: Request, user=Depends(require_referent)):
    """Importe un fichier Excel (.xlsx) et ajoute les contacts manquants.
    Détecte les doublons par (prenom+nom) ou telephone ou email.
    Les colonnes reconnues: Prenom, Nom, qualite, numero de telephone, email, Notes
    Les en-têtes sont comparées insensiblement à la casse et aux accents.
    """
    import openpyxl
    import unicodedata

    form = await request.form()
    file = form.get("file")
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="Fichier Excel requis")

    content = await file.read()
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        wb = openpyxl.load_workbook(tmp_path, data_only=True)
    except Exception as e:
        os.unlink(tmp_path)
        raise HTTPException(status_code=400, detail=f"Erreur lecture Excel: {str(e)}")
    
    ws = wb[wb.sheetnames[0]]
    
    # Lire les en-tetes (ligne 1)
    headers_raw = []
    for col in range(1, ws.max_column + 1):
        val = ws.cell(row=1, column=col).value
        headers_raw.append(str(val).strip() if val else "")
    
    # Normaliser les en-tetes (minuscules, sans accents, sans espaces)
    def normalize_header(h):
        h = h.lower().strip()
        h = unicodedata.normalize('NFD', h).encode('ascii', 'ignore').decode()
        h = re.sub(r'[^a-z0-9]', '', h)
        return h
    
    headers_norm = [normalize_header(h) for h in headers_raw]
    
    # Mapper les colonnes - recherche flexible
    col_map = {}
    for i, h in enumerate(headers_norm):
        if h in ("prenom", "firstname", "first") or "prenom" in h:
            col_map["prenom"] = i + 1
        elif h in ("nom", "lastname", "name", "lastname") or "nom" in h and "prenom" not in h:
            col_map["nom"] = i + 1
        elif h in ("qualite", "role", "fonction", "qualite") or "qualite" in h:
            col_map["qualite"] = i + 1
        elif "telephone" in h or "tel" in h or "phone" in h or "mobile" in h:
            col_map["telephone"] = i + 1
        elif "email" in h or "mail" in h or "courriel" in h:
            col_map["email"] = i + 1
        elif "note" in h:
            col_map["notes"] = i + 1
    
    # Lire les donnees
    rows = []
    for row_idx in range(2, ws.max_row + 1):
        row_data = {}
        for field, col_num in col_map.items():
            val = ws.cell(row=row_idx, column=col_num).value
            row_data[field] = str(val).strip() if val else ""
        
        # Skip empty rows
        if not row_data.get("prenom") and not row_data.get("nom"):
            continue
        rows.append(row_data)
    
    os.unlink(tmp_path)
    
    if not rows:
        raise HTTPException(status_code=400, detail="Aucune ligne trouvee dans le fichier Excel")
    
    # Importer dans la base
    data = load_db()
    existing = data["contacts"]
    
    def find_duplicate(row):
        for c in existing:
            # Match par prenom+nom (insensible casse)
            if row.get("prenom", "").lower() == c.get("prenom", "").lower() and \
               row.get("nom", "").upper() == c.get("nom", "").upper():
                return c
            # Match par telephone normalise
            row_tel = normalize_phone(row.get("telephone", ""))
            if row_tel and row_tel == c.get("telephone", ""):
                return c
            # Match par email
            row_email = row.get("email", "").lower()
            if row_email and row_email == c.get("email", "").lower():
                return c
        return None
    
    added = []
    skipped = []
    
    for row in rows:
        dup = find_duplicate(row)
        if dup:
            skipped.append(f"{row.get('prenom','')} {row.get('nom','')}")
            continue
        
        contact = {
            "id": gen_id(),
            "prenom": row.get("prenom", "").strip(),
            "nom": row.get("nom", "").strip().upper(),
            "qualite": row.get("qualite", "").strip(),
            "telephone": normalize_phone(row.get("telephone", "")),
            "email": row.get("email", "").strip().lower(),
            "notes": row.get("notes", "").strip(),
            "historique": [],
            "cree_par": user["username"],
            "cree_le": now_iso(),
            "modifie_par": "",
            "modifie_le": ""
        }
        add_history(contact, user, "import_excel", f"Importe depuis Excel par {user['username']}")
        existing.append(contact)
        added.append(f"{contact['prenom']} {contact['nom']}")
    
    if added:
        save_db(data)
        backup_db()
    
    return {
        "status": "ok",
        "total_lignes": len(rows),
        "ajoutes": len(added),
        "doublons_ignores": len(skipped),
        "nouveaux": added,
        "deja_existants": skipped,
        "colonnes_detectees": {k: headers_raw[v-1] for k, v in col_map.items()}
    }



# ============ GROUPES DE DIFFUSION ============
@app.get("/api/groupes/diffusion")
async def get_groupes_diffusion(user=Depends(require_referent)):
    """Retourne les groupes de diffusion par qualite avec le nombre de contacts ayant un email."""
    data = load_db()
    contacts = data["contacts"]
    groupes = {}
    for c in contacts:
        q = c.get("qualite", "non specifie") or "non specifie"
        if q not in groupes:
            groupes[q] = {"qualite": q, "total": 0, "avec_email": 0, "contacts": []}
        groupes[q]["total"] += 1
        if c.get("email"):
            groupes[q]["avec_email"] += 1
            groupes[q]["contacts"].append({"id": c["id"], "nom": f"{c.get('prenom','')} {c.get('nom','')}".strip(), "email": c["email"]})
    return list(groupes.values())

@app.post("/api/groupes/diffusion/send")
async def send_groupe_diffusion(req: EmailSend, user=Depends(require_referent)):
    """Envoie un email a un groupe de diffusion (contact_ids pre-remplis par le frontend)."""
    data = load_db()
    recipients = list(req.recipients)
    for cid in req.contact_ids:
        for c in data["contacts"]:
            if c["id"] == cid and c.get("email"):
                recipients.append(c["email"])
    recipients = list(set(r for r in recipients if r))
    if not recipients:
        raise HTTPException(status_code=400, detail="Aucun destinataire avec email")
    try:
        send_email_smtp(recipients, req.subject, req.body, html=req.html)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur envoi email: {str(e)}")
    for cid in req.contact_ids:
        for c in data["contacts"]:
            if c["id"] == cid:
                add_history(c, user, "email_groupe", f"Sujet: {req.subject} | A: {len(recipients)} destinataires")
    save_db(data)
    return {"status": "ok", "sent_to": recipients, "count": len(recipients)}

# ============ DASHBOARD DES ACTIVITES ============
@app.get("/api/dashboard")
async def get_dashboard(user=Depends(require_referent)):
    """Tableau de bord synthetique: activites recentes, cotisations en retard, prochaines echeances, contacts non contactes."""
    data = load_db()
    contacts = data["contacts"]
    today = datetime.now()
    annee_courante = str(today.year)
    
    # 1. Activites recentes (historique des 7 derniers jours)
    activites_recentes = []
    for c in contacts:
        for h in c.get("historique", []):
            try:
                h_date = datetime.fromisoformat(h.get("date", ""))
                if (today - h_date).days <= 7:
                    activites_recentes.append({
                        "date": h["date"],
                        "user": h.get("user", ""),
                        "action": h.get("action", ""),
                        "contact": f"{c.get('prenom','')} {c.get('nom','')}".strip(),
                        "contact_id": c["id"],
                        "details": h.get("details", "")
                    })
            except Exception:
                continue
    activites_recentes.sort(key=lambda x: x["date"], reverse=True)
    activites_recentes = activites_recentes[:20]
    
    # 2. Cotisations en retard (annee courante, non payees)
    cotisations_retard = []
    contact_by_id = {c["id"]: c for c in contacts}
    for cot in data.get("cotisations", []):
        if cot.get("annee") == annee_courante and cot.get("statut") != "paye":
            c = contact_by_id.get(cot.get("contact_id"), {})
            cotisations_retard.append({
                "contact_nom": f"{c.get('prenom','')} {c.get('nom','')}".strip(),
                "contact_id": cot.get("contact_id"),
                "montant": cot.get("montant", 0),
                "statut": cot.get("statut", ""),
                "date_paiement": cot.get("date_paiement", "")
            })
    
    # 3. Contacts sans cotisation pour l'annee courante
    contacts_avec_cot = {cot.get("contact_id") for cot in data.get("cotisations", []) if cot.get("annee") == annee_courante}
    contacts_sans_cot = []
    for c in contacts:
        if c["id"] not in contacts_avec_cot:
            contacts_sans_cot.append({
                "nom": f"{c.get('prenom','')} {c.get('nom','')}".strip(),
                "id": c["id"],
                "email": c.get("email", ""),
                "qualite": c.get("qualite", "")
            })
    
    # 4. Taches a venir (echeance dans les 30 prochains jours, non terminees)
    taches_a_venir = []
    for t in data.get("taches", []):
        if t.get("statut") != "terminee" and t.get("echeance"):
            try:
                echeance = datetime.strptime(t["echeance"], "%Y-%m-%d")
                if 0 <= (echeance - today).days <= 30:
                    contact = contact_by_id.get(t.get("assigne_a", ""), {})
                    taches_a_venir.append({
                        "titre": t.get("titre", ""),
                        "echeance": t["echeance"],
                        "priorite": t.get("priorite", "normale"),
                        "contact_nom": f"{contact.get('prenom','')} {contact.get('nom','')}".strip(),
                        "jours_restants": (echeance - today).days
                    })
            except Exception:
                continue
    taches_a_venir.sort(key=lambda x: x["echeance"])
    
    # 5. Prochains evenements
    prochains_evenements = []
    for ev in data.get("evenements", []):
        try:
            ev_date = datetime.strptime(ev.get("date", ""), "%Y-%m-%d")
            if ev_date >= today:
                prochains_evenements.append({
                    "titre": ev.get("titre", ""),
                    "date": ev.get("date", ""),
                    "lieu": ev.get("lieu", ""),
                    "jours_restants": (ev_date - today).days
                })
        except Exception:
            continue
    prochains_evenements.sort(key=lambda x: x["date"])
    
    # 6. Contacts non contactes depuis plus de 90 jours
    contacts_non_contactes = []
    for c in contacts:
        derniere_activite = c.get("modifie_le", "") or c.get("cree_le", "")
        for h in c.get("historique", []):
            if h.get("date", "") > derniere_activite:
                derniere_activite = h["date"]
        if derniere_activite:
            try:
                d = datetime.fromisoformat(derniere_activite)
                if (today - d).days > 90:
                    contacts_non_contactes.append({
                        "nom": f"{c.get('prenom','')} {c.get('nom','')}".strip(),
                        "id": c["id"],
                        "derniere_activite": derniere_activite[:10],
                        "jours": (today - d).days
                    })
            except Exception:
                continue
    
    return {
        "activites_recentes": activites_recentes,
        "cotisations_retard": cotisations_retard,
        "contacts_sans_cotisation": contacts_sans_cot,
        "taches_a_venir": taches_a_venir,
        "prochains_evenements": prochains_evenements,
        "contacts_non_contactes": contacts_non_contactes,
        "total_contacts": len(contacts),
        "total_cotisations_annee": len([c for c in data.get("cotisations",[]) if c.get("annee") == annee_courante]),
        "total_taches_actives": len([t for t in data.get("taches",[]) if t.get("statut") != "terminee"])
    }

# ============ RELANCE COTISATIONS ============
@app.post("/api/cotisations/relance")
async def relance_cotisations(annee: str = "", user=Depends(require_referent)):
    """Envoie un email de relance aux contacts sans cotisation payee pour l'annee donnee (defaut: annee courante)."""
    data = load_db()
    annee_cible = annee or str(datetime.now().year)
    
    # Trouver les contacts sans cotisation payee
    contacts_avec_cot_payee = {
        cot.get("contact_id") for cot in data.get("cotisations", [])
        if cot.get("annee") == annee_cible and cot.get("statut") == "paye"
    }
    
    a_relancer = []
    for c in data["contacts"]:
        if c["id"] not in contacts_avec_cot_payee and c.get("email"):
            a_relancer.append(c)
    
    if not a_relancer:
        return {"status": "ok", "envoyes": 0, "message": "Aucun contact a relancer (tous a jour ou sans email)"}
    
    subject = f"Relance cotisation {annee_cible} - Les Ami(e)s de Romy"
    body = f"""Bonjour,

Nous vous contactons concernant votre cotisation annuelle {annee_cible} pour l association Les Ami(e)s de Romy.

Si vous avez deja regle votre cotisation, merci d ignorer cet email.
Sinon, nous vous invitons a regulariser votre situation.

Montant de la cotisation: a definir selon le barème de l association.
Mode de paiement: especes, cheque ou virement.

Pour toute question, n hesitez pas a nous contacter.

Cordialement,
L equipe des Ami(e)s de Romy"""
    
    recipients = [c["email"] for c in a_relancer]
    try:
        send_email_smtp(recipients, subject, body)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur envoi email: {str(e)}")
    
    for c in a_relancer:
        add_history(c, user, "relance_cotisation", f"Relance cotisation {annee_cible} envoyee")
    save_db(data)
    
    return {"status": "ok", "envoyes": len(recipients), "destinataires": [c["email"] for c in a_relancer]}


# ============ F1: TABLEAU DE BORD D'IMPACT ============
@app.get("/api/impact")
async def get_impact(user=Depends(require_referent)):
    """Statistiques d'impact pour la prévention des violences infantiles."""
    data = load_db()
    contacts = data.get("contacts", [])
    events = data.get("evenements", [])
    cots = data.get("cotisations", [])
    dons = data.get("dons", [])
    accomps = data.get("accompagnements", [])

    now = datetime.now()
    year = str(now.year)

    # Dons par mois (12 derniers mois)
    dons_par_mois = {}
    for d in dons:
        dt = d.get("date", "")
        if dt and len(dt) >= 7:
            dons_par_mois[dt[:7]] = dons_par_mois.get(dt[:7], 0) + d.get("montant", 0)

    # Cotisations par année
    cots_par_annee = {}
    for c in cots:
        an = c.get("annee", "")
        if an:
            cots_par_annee[an] = cots_par_annee.get(an, 0) + c.get("montant", 0)

    # Contacts par qualité
    par_qualite = {}
    for c in contacts:
        q = c.get("qualite", "sans qualite")
        par_qualite[q] = par_qualite.get(q, 0) + 1

    # Événements par mois
    events_par_mois = {}
    for e in events:
        dt = e.get("date", "")
        if dt and len(dt) >= 7:
            events_par_mois[dt[:7]] = events_par_mois.get(dt[:7], 0) + 1

    # Accompagnements actifs
    accomp_actifs = [a for a in accomps if a.get("statut") == "actif"]
    accomp_par_type = {}
    for a in accomps:
        t = a.get("type_suivi", "accompagnement")
        accomp_par_type[t] = accomp_par_type.get(t, 0) + 1

    # Présence totale aux événements
    presence_total = 0
    for e in events:
        p = e.get("presence", {})
        presence_total += sum(1 for v in p.values() if v == "present")

    return {
        "contacts_total": len(contacts),
        "contacts_par_qualite": par_qualite,
        "events_total": len(events),
        "events_par_mois": events_par_mois,
        "presence_total": presence_total,
        "cots_par_annee": cots_par_annee,
        "dons_total": sum(d.get("montant", 0) for d in dons),
        "dons_par_mois": dons_par_mois,
        "accomp_total": len(accomps),
        "accomp_actifs": len(accomp_actifs),
        "accomp_par_type": accomp_par_type,
        "benevoles_actifs": len([c for c in contacts if c.get("qualite", "") in ("referent", "benevole", "membre asso")]),
    }


# ============ F2: CARTOGRAPHIE INTERVENANTS/PARTENAIRES ============
@app.get("/api/cartographie")
async def get_cartographie(user=Depends(require_referent)):
    """Retourne les contacts avec code postal/ville pour cartographie Leaflet."""
    data = load_db()
    contacts = data.get("contacts", [])
    points = []
    for c in contacts:
        cp = c.get("code_postal") or c.get("cp") or ""
        ville = c.get("ville") or ""
        # Extract from notes if not available
        if not cp and c.get("notes", ""):
            import re
            m = re.search(r'\b(\d{5})\b', c.get("notes", ""))
            if m:
                cp = m.group(1)
        if cp or ville:
            points.append({
                "id": c["id"],
                "nom": f"{c.get('prenom','')} {c.get('nom','')}",
                "qualite": c.get("qualite", ""),
                "email": c.get("email", ""),
                "telephone": c.get("telephone", ""),
                "code_postal": cp,
                "ville": ville,
                "notes": c.get("notes", "")[:100]
            })
    return {"points": points, "total": len(points)}


# ============ F3: SUIVI D'ACCOMPAGNEMENT FAMILIAL ============
@app.get("/api/accompagnements")
async def list_accompagnements(statut: str = "", user=Depends(require_referent)):
    data = load_db()
    accomps = data.get("accompagnements", [])
    if statut:
        accomps = [a for a in accomps if a.get("statut") == statut]
    # Enrich with contact name
    contact_by_id = {c["id"]: c for c in data["contacts"]}
    for a in accomps:
        c = contact_by_id.get(a["contact_id"])
        a["contact_nom"] = f"{c.get('prenom','')} {c.get('nom','')}" if c else "?"
        # Hide confidential notes from non-admin
        if user["role"] != "admin":
            a.pop("notes_confidentielles", None)
    return accomps

@app.post("/api/accompagnements")
async def create_accompagnement(req: AccompagnementCreate, user=Depends(require_referent)):
    data = load_db()
    if "accompagnements" not in data:
        data["accompagnements"] = []
    a = {
        "id": f"acc-{secrets.token_hex(8)}",
        "contact_id": req.contact_id,
        "type_suivi": req.type_suivi,
        "date_debut": req.date_debut,
        "date_fin": req.date_fin,
        "statut": req.statut,
        "priorite": req.priorite,
        "intervenants": req.intervenants,
        "notes_confidentielles": req.notes_confidentielles,
        "notes_partagees": req.notes_partagees,
        "historique": [{"date": now_iso(), "user": user["username"], "action": "creation"}],
        "cree_par": user["username"],
        "cree_le": now_iso()
    }
    data["accompagnements"].append(a)
    save_db(data)
    backup_db()
    return {"status": "ok", "accompagnement": a}

@app.put("/api/accompagnements/{acc_id}")
async def update_accompagnement(acc_id: str, req: AccompagnementUpdate, user=Depends(require_referent)):
    data = load_db()
    for a in data.get("accompagnements", []):
        if a["id"] == acc_id:
            changes = []
            for field in ["type_suivi", "date_debut", "date_fin", "statut", "priorite", "intervenants", "notes_partagees"]:
                val = getattr(req, field)
                if val is not None and a.get(field) != val:
                    changes.append(f"{field} modifie")
                    a[field] = val
            # Confidential notes only for admin
            if req.notes_confidentielles is not None and user["role"] == "admin":
                a["notes_confidentielles"] = req.notes_confidentielles
                changes.append("notes confidentielles modifiees")
            if changes:
                a["historique"].append({"date": now_iso(), "user": user["username"], "action": "modification", "details": " | ".join(changes)})
                save_db(data)
                backup_db()
            return {"status": "ok", "accompagnement": a}
    raise HTTPException(status_code=404, detail="Accompagnement non trouve")

@app.post("/api/accompagnements/{acc_id}/notes")
async def add_accompagnement_note(acc_id: str, req: AccompagnementNote, user=Depends(require_referent)):
    data = load_db()
    for a in data.get("accompagnements", []):
        if a["id"] == acc_id:
            entry = {
                "date": now_iso(),
                "user": user["username"],
                "note": req.note,
                "confidentiel": req.confidentiel and user["role"] == "admin"
            }
            a.setdefault("notes_historique", []).append(entry)
            a["historique"].append({"date": now_iso(), "user": user["username"], "action": "note", "details": req.note[:80]})
            save_db(data)
            backup_db()
            return {"status": "ok"}
    raise HTTPException(status_code=404, detail="Accompagnement non trouve")

@app.delete("/api/accompagnements/{acc_id}")
async def delete_accompagnement(acc_id: str, user=Depends(require_referent)):
    data = load_db()
    data["accompagnements"] = [a for a in data.get("accompagnements", []) if a["id"] != acc_id]
    save_db(data)
    backup_db()
    return {"status": "ok"}


# ============ F4: PLANNING PRESENCE BENEVOLS ============
@app.get("/api/planning")
async def get_planning(evenement_id: str = "", user=Depends(require_auth)):
    data = load_db()
    planning = data.get("planning_benevoles", [])
    if evenement_id:
        planning = [p for p in planning if p["evenement_id"] == evenement_id]
    contact_by_id = {c["id"]: c for c in data["contacts"]}
    for p in planning:
        c = contact_by_id.get(p["contact_id"])
        p["contact_nom"] = f"{c.get('prenom','')} {c.get('nom','')}" if c else "?"
    return planning

@app.post("/api/planning")
async def set_planning(req: BenevolePlanning, user=Depends(require_referent)):
    data = load_db()
    if "planning_benevoles" not in data:
        data["planning_benevoles"] = []
    # Remove existing entry for same event+contact, then add
    data["planning_benevoles"] = [p for p in data["planning_benevoles"]
                                  if not (p["evenement_id"] == req.evenement_id and p["contact_id"] == req.contact_id)]
    entry = {
        "id": f"plan-{secrets.token_hex(8)}",
        "evenement_id": req.evenement_id,
        "contact_id": req.contact_id,
        "role": req.role,
        "creneau": req.creneau,
        "cree_par": user["username"],
        "cree_le": now_iso()
    }
    data["planning_benevoles"].append(entry)
    save_db(data)
    backup_db()
    return {"status": "ok", "planning": entry}

@app.delete("/api/planning/{plan_id}")
async def delete_planning(plan_id: str, user=Depends(require_referent)):
    data = load_db()
    data["planning_benevoles"] = [p for p in data.get("planning_benevoles", []) if p["id"] != plan_id]
    save_db(data)
    backup_db()
    return {"status": "ok"}


# ============ F5: GENERATEUR RAPPORTS D'ACTIVITE ============
@app.get("/api/rapport-activite")
async def generate_rapport(annee: str = "", token: str = ""):
    """Genere un rapport d'activite au format HTML (pour impression PDF navigateur). Token en query car window.open ne peut pas envoyer de header."""
    user = get_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Token invalide")
    if user["role"] not in REFERENT_ROLES:
        raise HTTPException(status_code=403, detail="Acces referent requis")
    data = load_db()
    annee_cible = annee or str(datetime.now().year)
    contacts = data.get("contacts", [])
    events = data.get("evenements", [])
    cots = data.get("cotisations", [])
    dons = data.get("dons", [])
    accomps = data.get("accompagnements", [])

    # Filter by year
    events_an = [e for e in events if e.get("date", "").startswith(annee_cible)]
    cots_an = [c for c in cots if c.get("annee") == annee_cible]
    dons_an = [d for d in dons if d.get("date", "").startswith(annee_cible)]
    accomp_an = [a for a in accomps if a.get("date_debut", "").startswith(annee_cible)]

    total_cots = sum(c.get("montant", 0) for c in cots_an)
    total_dons = sum(d.get("montant", 0) for d in dons_an)

    # Presence stats
    presence_total = sum(sum(1 for v in e.get("presence", {}).values() if v == "present") for e in events_an)

    html = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Rapport d activite {annee_cible}</title>
<style>
body{{font-family:Arial,sans-serif;max-width:800px;margin:0 auto;padding:2rem;color:#333}}
h1{{color:#d03ec6;text-align:center;border-bottom:3px solid #d03ec6;padding-bottom:.5rem}}
h2{{color:#9e2b94;margin-top:2rem}}
.stat-box{{display:inline-block;width:45%;margin:1%;padding:1rem;background:#f3e0f5;border-radius:10px;text-align:center}}
.stat-box .num{{font-size:2rem;font-weight:bold;color:#d03ec6}}
.stat-box .lbl{{font-size:.85rem;color:#666}}
table{{width:100%;border-collapse:collapse;margin:1rem 0}}
th{{background:#d03ec6;color:#fff;padding:.5rem;text-align:left}}
td{{padding:.5rem;border-bottom:1px solid #eee}}
.footer{{margin-top:3rem;text-align:center;font-size:.8rem;color:#999}}
</style></head><body>
<h1>Rapport d activite {annee_cible}</h1>
<p style="text-align:center;color:#666">Les Ami(e)s de Romy — Prevention des violences infantiles</p>

<h2>Chiffres cles</h2>
<div class="stat-box"><div class="num">{len(contacts)}</div><div class="lbl">Contacts total</div></div>
<div class="stat-box"><div class="num">{len(events_an)}</div><div class="lbl">Evenements {annee_cible}</div></div>
<div class="stat-box"><div class="num">{presence_total}</div><div class="lbl">Presences aux evenements</div></div>
<div class="stat-box"><div class="num">{len(accomp_an)}</div><div class="lbl">Accompagnements</div></div>
<div class="stat-box"><div class="num">{total_cots:.0f} &euro;</div><div class="lbl">Cotisations {annee_cible}</div></div>
<div class="stat-box"><div class="num">{total_dons:.0f} &euro;</div><div class="lbl">Dons {annee_cible}</div></div>

<h2>Evenements de l annee</h2>
<table><tr><th>Date</th><th>Titre</th><th>Lieu</th><th>Presences</th></tr>"""
    for e in events_an:
        pres = sum(1 for v in e.get("presence", {}).values() if v == "present")
        html += f"<tr><td>{e.get('date','')}</td><td>{e.get('titre','')}</td><td>{e.get('lieu','')}</td><td>{pres}</td></tr>"
    html += "</table>"

    html += f"<h2>Dons de l annee</h2><table><tr><th>Date</th><th>Nom</th><th>Montant</th></tr>"
    for d in dons_an:
        html += f"<tr><td>{d.get('date','')}</td><td>{d.get('nom','')}</td><td>{d.get('montant',0)} &euro;</td></tr>"
    html += "</table>"

    html += f"<h2>Accompagnements {annee_cible}</h2><table><tr><th>Type</th><th>Statut</th><th>Priorite</th></tr>"
    for a in accomp_an:
        html += f"<tr><td>{a.get('type_suivi','')}</td><td>{a.get('statut','')}</td><td>{a.get('priorite','')}</td></tr>"
    html += "</table>"

    html += f'<div class="footer">Genere le {datetime.now().strftime("%d/%m/%Y")} par {user["username"]} — CRM Les Ami(e)s de Romy v{VERSION}</div>'
    html += "</body></html>"

    return HTMLResponse(content=html)


# ============ F6: NOTES DE FRAIS ============
@app.get("/api/notes-frais")
async def list_notes_frais(statut: str = "", user=Depends(require_referent)):
    data = load_db()
    notes = data.get("notes_frais", [])
    if statut:
        notes = [n for n in notes if n.get("statut") == statut]
    contact_by_id = {c["id"]: c for c in data["contacts"]}
    for n in notes:
        c = contact_by_id.get(n.get("contact_id", ""))
        n["contact_nom"] = f"{c.get('prenom','')} {c.get('nom','')}" if c else n.get("contact_nom", "-")
    return notes

@app.post("/api/notes-frais")
async def create_note_frais(req: NoteFraisCreate, user=Depends(require_referent)):
    data = load_db()
    if "notes_frais" not in data:
        data["notes_frais"] = []
    n = {
        "id": f"nf-{secrets.token_hex(8)}",
        "contact_id": req.contact_id,
        "date": req.date,
        "montant": req.montant,
        "categorie": req.categorie,
        "description": req.description,
        "justificatif": req.justificatif,
        "statut": req.statut,
        "cree_par": user["username"],
        "cree_le": now_iso()
    }
    data["notes_frais"].append(n)
    save_db(data)
    backup_db()
    return {"status": "ok", "note_frais": n}

@app.put("/api/notes-frais/{nf_id}")
async def update_note_frais(nf_id: str, req: NoteFraisUpdate, user=Depends(require_referent)):
    data = load_db()
    for n in data.get("notes_frais", []):
        if n["id"] == nf_id:
            if req.montant is not None: n["montant"] = req.montant
            if req.categorie is not None: n["categorie"] = req.categorie
            if req.description is not None: n["description"] = req.description
            if req.statut is not None: n["statut"] = req.statut
            save_db(data); backup_db()
            return {"status": "ok", "note_frais": n}
    raise HTTPException(status_code=404, detail="Note de frais non trouvee")

@app.delete("/api/notes-frais/{nf_id}")
async def delete_note_frais(nf_id: str, user=Depends(require_referent)):
    data = load_db()
    data["notes_frais"] = [n for n in data.get("notes_frais", []) if n["id"] != nf_id]
    save_db(data); backup_db()
    return {"status": "ok"}

@app.get("/api/notes-frais/total")
async def total_notes_frais(user=Depends(require_referent)):
    data = load_db()
    notes = data.get("notes_frais", [])
    return {
        "total": sum(n.get("montant", 0) for n in notes),
        "en_attente": sum(n.get("montant", 0) for n in notes if n.get("statut") == "en_attente"),
        "valide": sum(n.get("montant", 0) for n in notes if n.get("statut") == "valide"),
        "rembourse": sum(n.get("montant", 0) for n in notes if n.get("statut") == "rembourse"),
        "count": len(notes)
    }


# ============ F7: ECHEANCES & RAPPELS ============
@app.get("/api/echeances")
async def list_echeances(statut: str = "", user=Depends(require_referent)):
    data = load_db()
    echeances = data.get("echeances", [])
    # Auto-update overdue status
    today = datetime.now().strftime("%Y-%m-%d")
    for e in echeances:
        if e.get("statut") == "a_venir" and e.get("date") and e["date"] < today:
            e["statut"] = "en_retard"
    if statut:
        echeances = [e for e in echeances if e.get("statut") == statut]
    save_db(data)  # persist status changes
    return echeances

@app.post("/api/echeances")
async def create_echeance(req: EcheanceCreate, user=Depends(require_referent)):
    data = load_db()
    if "echeances" not in data:
        data["echeances"] = []
    e = {
        "id": f"ech-{secrets.token_hex(8)}",
        "titre": req.titre,
        "date": req.date,
        "type_echeance": req.type_echeance,
        "description": req.description,
        "recursif": req.recursif,
        "responsable": req.responsable,
        "statut": "a_venir",
        "cree_par": user["username"],
        "cree_le": now_iso()
    }
    data["echeances"].append(e)
    save_db(data); backup_db()
    return {"status": "ok", "echeance": e}

@app.put("/api/echeances/{ech_id}")
async def update_echeance(ech_id: str, req: EcheanceUpdate, user=Depends(require_referent)):
    data = load_db()
    for e in data.get("echeances", []):
        if e["id"] == ech_id:
            for f in ["titre", "date", "type_echeance", "description", "recursif", "responsable", "statut"]:
                val = getattr(req, f)
                if val is not None: e[f] = val
            # If marked done and recursive, create next occurrence
            if req.statut == "fait" and e.get("recursif") and e.get("date"):
                d = datetime.strptime(e["date"], "%Y-%m-%d")
                if e["recursif"] == "annuel":
                    d = d.replace(year=d.year + 1)
                elif e["recursif"] == "mensuel":
                    # stdlib month increment
                    m = d.month + 1
                    y = d.year
                    if m > 12: m = 1; y += 1
                    import calendar
                    last_day = calendar.monthrange(y, m)[1]
                    d = d.replace(year=y, month=m, day=min(d.day, last_day))
                new_e = dict(e)
                new_e["id"] = f"ech-{secrets.token_hex(8)}"
                new_e["date"] = d.strftime("%Y-%m-%d")
                new_e["statut"] = "a_venir"
                new_e["cree_le"] = now_iso()
                data["echeances"].append(new_e)
            save_db(data); backup_db()
            return {"status": "ok", "echeance": e}
    raise HTTPException(status_code=404, detail="Echeance non trouvee")

@app.delete("/api/echeances/{ech_id}")
async def delete_echeance(ech_id: str, user=Depends(require_referent)):
    data = load_db()
    data["echeances"] = [e for e in data.get("echeances", []) if e["id"] != ech_id]
    save_db(data); backup_db()
    return {"status": "ok"}


# ============ F8: REGISTRE DES APPELS ============
@app.get("/api/registre-appels")
async def list_registre_appels(motif: str = "", user=Depends(require_referent)):
    data = load_db()
    appels = data.get("registre_appels", [])
    if motif:
        appels = [a for a in appels if a.get("motif") == motif]
    contact_by_id = {c["id"]: c for c in data["contacts"]}
    for a in appels:
        c = contact_by_id.get(a.get("contact_id", ""))
        a["contact_nom"] = f"{c.get('prenom','')} {c.get('nom','')}" if c else ""
    return appels

@app.post("/api/registre-appels")
async def create_registre_appel(req: RegistreAppelCreate, user=Depends(require_referent)):
    data = load_db()
    if "registre_appels" not in data:
        data["registre_appels"] = []
    a = {
        "id": f"app-{secrets.token_hex(8)}",
        "contact_id": req.contact_id,
        "nom_appelant": req.nom_appelant,
        "nom_appele": req.nom_appele,
        "date_appel": req.date_appel,
        "heure": req.heure,
        "motif": req.motif,
        "description": req.description,
        "suite_donnee": req.suite_donnee,
        "cree_par": user["username"],
        "cree_le": now_iso()
    }
    data["registre_appels"].append(a)
    save_db(data); backup_db()
    return {"status": "ok", "appel": a}

@app.delete("/api/registre-appels/{appel_id}")
async def delete_registre_appel(appel_id: str, user=Depends(require_referent)):
    data = load_db()
    data["registre_appels"] = [a for a in data.get("registre_appels", []) if a["id"] != appel_id]
    save_db(data); backup_db()
    return {"status": "ok"}


# ============ F9: VOTES / SCRUTINS AG ============
@app.get("/api/votes")
async def list_votes(user=Depends(require_referent)):
    data = load_db()
    return data.get("votes", [])

@app.post("/api/votes")
async def create_vote(req: VoteCreate, user=Depends(require_referent)):
    data = load_db()
    if "votes" not in data:
        data["votes"] = []
    v = {
        "id": f"vote-{secrets.token_hex(8)}",
        "titre": req.titre,
        "date": req.date,
        "type_vote": req.type_vote,
        "description": req.description,
        "resultat": {"pour": 0, "contre": 0, "abstention": 0},
        "notes": "",
        "statut": "ouvert",  # ouvert, cloture
        "cree_par": user["username"],
        "cree_le": now_iso()
    }
    data["votes"].append(v)
    save_db(data); backup_db()
    return {"status": "ok", "vote": v}

@app.put("/api/votes/{vote_id}")
async def update_vote_resultat(vote_id: str, req: VoteResultat, user=Depends(require_referent)):
    data = load_db()
    for v in data.get("votes", []):
        if v["id"] == vote_id:
            v["resultat"] = {"pour": req.pour, "contre": req.contre, "abstention": req.abstention}
            v["notes"] = req.notes
            v["statut"] = "cloture"
            save_db(data); backup_db()
            return {"status": "ok", "vote": v}
    raise HTTPException(status_code=404, detail="Vote non trouve")

@app.delete("/api/votes/{vote_id}")
async def delete_vote(vote_id: str, user=Depends(require_referent)):
    data = load_db()
    data["votes"] = [v for v in data.get("votes", []) if v["id"] != vote_id]
    save_db(data); backup_db()
    return {"status": "ok"}


# ============ F10: CHECKLISTS RECURRENTES ============
@app.get("/api/checklists")
async def list_checklists(type_checklist: str = "", user=Depends(require_referent)):
    data = load_db()
    cls = data.get("checklists", [])
    if type_checklist:
        cls = [c for c in cls if c.get("type_checklist") == type_checklist]
    return cls

@app.post("/api/checklists")
async def create_checklist(req: ChecklistCreate, user=Depends(require_referent)):
    data = load_db()
    if "checklists" not in data:
        data["checklists"] = []
    c = {
        "id": f"chk-{secrets.token_hex(8)}",
        "titre": req.titre,
        "type_checklist": req.type_checklist,
        "evenement_id": req.evenement_id,
        "taches": req.taches,
        "coche": [False] * len(req.taches),
        "statut": "en_cours",
        "cree_par": user["username"],
        "cree_le": now_iso()
    }
    data["checklists"].append(c)
    save_db(data); backup_db()
    return {"status": "ok", "checklist": c}

@app.put("/api/checklists/{chk_id}")
async def update_checklist(chk_id: str, req: ChecklistUpdate, user=Depends(require_referent)):
    data = load_db()
    for c in data.get("checklists", []):
        if c["id"] == chk_id:
            if req.taches is not None:
                c["taches"] = req.taches
                c["coche"] = req.coche or [False] * len(req.taches)
            elif req.coche is not None:
                c["coche"] = req.coche
            # Check if all done
            if all(c["coche"]):
                c["statut"] = "termine"
            save_db(data); backup_db()
            return {"status": "ok", "checklist": c}
    raise HTTPException(status_code=404, detail="Checklist non trouvee")

@app.delete("/api/checklists/{chk_id}")
async def delete_checklist(chk_id: str, user=Depends(require_referent)):
    data = load_db()
    data["checklists"] = [c for c in data.get("checklists", []) if c["id"] != chk_id]
    save_db(data); backup_db()
    return {"status": "ok"}


# ============ F11: SONDAGES RAPIDES ============
@app.get("/api/sondages")
async def list_sondages(user=Depends(require_auth)):
    data = load_db()
    sondages = data.get("sondages", [])
    # Members see only sondages targeting them
    if user["role"] == "membre":
        sondages = [s for s in sondages if s.get("cible") in ("membres", "tous") and s.get("statut") == "ouvert"]
    # Add response counts
    for s in sondages:
        s["nb_repondants"] = len(s.get("reponses", {}))
        s["resultats"] = {}
        for r in s.get("reponses", {}).values():
            for idx in (r if isinstance(r, list) else [r]):
                s["resultats"][idx] = s["resultats"].get(idx, 0) + 1
    return sondages

@app.post("/api/sondages")
async def create_sondage(req: SondageCreate, user=Depends(require_referent)):
    data = load_db()
    if "sondages" not in data:
        data["sondages"] = []
    s = {
        "id": f"snd-{secrets.token_hex(8)}",
        "question": req.question,
        "options": req.options,
        "cible": req.cible,
        "date_fin": req.date_fin,
        "multiple": req.multiple,
        "statut": "ouvert",
        "reponses": {},  # {contact_id: option_index or [indexes]}
        "cree_par": user["username"],
        "cree_le": now_iso()
    }
    data["sondages"].append(s)
    save_db(data); backup_db()
    return {"status": "ok", "sondage": s}

@app.post("/api/sondages/{sondage_id}/repondre")
async def repondre_sondage(sondage_id: str, req: SondageReponse, user=Depends(require_auth)):
    data = load_db()
    for s in data.get("sondages", []):
        if s["id"] == sondage_id and s.get("statut") == "ouvert":
            cid = user.get("contact_id") or user["username"]
            if s.get("multiple"):
                # Toggle option
                current = s["reponses"].get(cid, [])
                if not isinstance(current, list): current = [current]
                if req.option_index in current:
                    current = [x for x in current if x != req.option_index]
                else:
                    current.append(req.option_index)
                s["reponses"][cid] = current
            else:
                s["reponses"][cid] = req.option_index
            save_db(data); backup_db()
            return {"status": "ok"}
    raise HTTPException(status_code=404, detail="Sondage non trouve ou cloture")

@app.put("/api/sondages/{sondage_id}/cloturer")
async def cloturer_sondage(sondage_id: str, user=Depends(require_referent)):
    data = load_db()
    for s in data.get("sondages", []):
        if s["id"] == sondage_id:
            s["statut"] = "cloture"
            save_db(data); backup_db()
            return {"status": "ok"}
    raise HTTPException(status_code=404, detail="Sondage non trouve")

@app.delete("/api/sondages/{sondage_id}")
async def delete_sondage(sondage_id: str, user=Depends(require_referent)):
    data = load_db()
    data["sondages"] = [s for s in data.get("sondages", []) if s["id"] != sondage_id]
    save_db(data); backup_db()
    return {"status": "ok"}


# ============ F12: COMPTES-RENDUS DE REUNIONS ============
@app.get("/api/comptes-rendus")
async def list_comptes_rendus(user=Depends(require_auth)):
    data = load_db()
    crs = data.get("comptes_rendus", [])
    contact_by_id = {c["id"]: c for c in data["contacts"]}
    for cr in crs:
        cr["presents_noms"] = [f"{contact_by_id.get(cid,{}).get('prenom','')} {contact_by_id.get(cid,{}).get('nom','')}" for cid in cr.get("presents", [])]
        cr["nb_presents"] = len(cr.get("presents", []))
    return crs

@app.get("/api/comptes-rendus/{cr_id}")
async def get_compte_rendu(cr_id: str, user=Depends(require_auth)):
    data = load_db()
    contact_by_id = {c["id"]: c for c in data["contacts"]}
    for cr in data.get("comptes_rendus", []):
        if cr["id"] == cr_id:
            cr["presents_noms"] = [f"{contact_by_id.get(cid,{}).get('prenom','')} {contact_by_id.get(cid,{}).get('nom','')}" for cid in cr.get("presents", [])]
            cr["absents_noms"] = [f"{contact_by_id.get(cid,{}).get('prenom','')} {contact_by_id.get(cid,{}).get('nom','')}" for cid in cr.get("absents", [])]
            cr["excused_noms"] = [f"{contact_by_id.get(cid,{}).get('prenom','')} {contact_by_id.get(cid,{}).get('nom','')}" for cid in cr.get("excused", [])]
            return cr
    raise HTTPException(status_code=404, detail="Compte-rendu non trouve")

@app.post("/api/comptes-rendus")
async def create_compte_rendu(req: CompteRenduCreate, user=Depends(require_referent)):
    data = load_db()
    if "comptes_rendus" not in data:
        data["comptes_rendus"] = []
    cr = {
        "id": f"cr-{secrets.token_hex(8)}",
        "titre": req.titre, "date": req.date, "type_reunion": req.type_reunion,
        "presents": req.presents, "absents": req.absents, "excused": req.excused,
        "ordre_du_jour": req.ordre_du_jour, "discussions": req.discussions,
        "decisions": req.decisions, "actions": req.actions,
        "cree_par": user["username"], "cree_le": now_iso()
    }
    data["comptes_rendus"].append(cr)
    save_db(data); backup_db()
    return {"status": "ok", "compte_rendu": cr}

@app.put("/api/comptes-rendus/{cr_id}")
async def update_compte_rendu(cr_id: str, req: CompteRenduUpdate, user=Depends(require_referent)):
    data = load_db()
    for cr in data.get("comptes_rendus", []):
        if cr["id"] == cr_id:
            for f in ["titre","date","type_reunion","presents","absents","excused","ordre_du_jour","discussions","decisions","actions"]:
                val = getattr(req, f)
                if val is not None: cr[f] = val
            save_db(data); backup_db()
            return {"status": "ok", "compte_rendu": cr}
    raise HTTPException(status_code=404, detail="Compte-rendu non trouve")

@app.delete("/api/comptes-rendus/{cr_id}")
async def delete_compte_rendu(cr_id: str, user=Depends(require_referent)):
    data = load_db()
    data["comptes_rendus"] = [cr for cr in data.get("comptes_rendus", []) if cr["id"] != cr_id]
    save_db(data); backup_db()
    return {"status": "ok"}


# ============ F13: CAMPAGNES SMS / WHATSAPP ============
@app.get("/api/sms-campaigns")
async def list_sms_campaigns(user=Depends(require_referent)):
    data = load_db()
    return data.get("sms_campaigns", [])

@app.post("/api/sms-campaigns")
async def create_sms_campaign(req: SmsCampaignCreate, user=Depends(require_referent)):
    data = load_db()
    if "sms_campaigns" not in data:
        data["sms_campaigns"] = []
    # Resolve contact_ids to phone numbers
    contacts = data.get("contacts", [])
    if req.qualite:
        req.contact_ids = [c["id"] for c in contacts if c.get("qualite") == req.qualite and c.get("telephone")]
    numeros = list(req.destinataires)
    for c in contacts:
        if c["id"] in req.contact_ids and c.get("telephone"):
            numeros.append(c["telephone"])
    # Deduplicate
    numeros = list(set(numeros))
    camp = {
        "id": f"sms-{secrets.token_hex(8)}",
        "message": req.message,
        "destinataires": numeros,
        "nb_destinataires": len(numeros),
        "statut": "prete",  # prete, envoyee, echec
        "cree_par": user["username"], "cree_le": now_iso()
    }
    data["sms_campaigns"].append(camp)
    save_db(data); backup_db()
    return {"status": "ok", "campaign": camp}

@app.post("/api/sms-campaigns/{camp_id}/send")
async def send_sms_campaign(camp_id: str, user=Depends(require_referent)):
    data = load_db()
    for camp in data.get("sms_campaigns", []):
        if camp["id"] == camp_id:
            # TODO: integrer Twilio/OVH/WhatsApp Business API
            # Pour l instant on marque comme envoyee
            camp["statut"] = "envoyee"
            camp["envoye_le"] = now_iso()
            save_db(data); backup_db()
            return {"status": "ok", "message": f"Campagne prete ({camp['nb_destinataires']} destinataires). Integration SMS a configurer.", "campaign": camp}
    raise HTTPException(status_code=404, detail="Campagne non trouvee")

@app.delete("/api/sms-campaigns/{camp_id}")
async def delete_sms_campaign(camp_id: str, user=Depends(require_referent)):
    data = load_db()
    data["sms_campaigns"] = [c for c in data.get("sms_campaigns", []) if c["id"] != camp_id]
    save_db(data); backup_db()
    return {"status": "ok"}


# ============ F14: RELATIONS PRESSE & MEDIAS ============
@app.get("/api/presse/contacts")
async def list_presse_contacts(user=Depends(require_referent)):
    data = load_db()
    return data.get("presse_contacts", [])

@app.post("/api/presse/contacts")
async def create_presse_contact(req: PresseContactCreate, user=Depends(require_referent)):
    data = load_db()
    if "presse_contacts" not in data:
        data["presse_contacts"] = []
    c = {"id": f"prs-{secrets.token_hex(8)}", **req.dict(), "cree_le": now_iso()}
    data["presse_contacts"].append(c)
    save_db(data); backup_db()
    return {"status": "ok", "contact": c}

@app.delete("/api/presse/contacts/{pc_id}")
async def delete_presse_contact(pc_id: str, user=Depends(require_referent)):
    data = load_db()
    data["presse_contacts"] = [c for c in data.get("presse_contacts", []) if c["id"] != pc_id]
    save_db(data); backup_db()
    return {"status": "ok"}

@app.get("/api/presse/releases")
async def list_presse_releases(user=Depends(require_referent)):
    data = load_db()
    return data.get("presse_releases", [])

@app.post("/api/presse/releases")
async def create_presse_release(req: PresseReleaseCreate, user=Depends(require_referent)):
    data = load_db()
    if "presse_releases" not in data:
        data["presse_releases"] = []
    r = {"id": f"rel-{secrets.token_hex(8)}", **req.dict(), "cree_par": user["username"], "cree_le": now_iso()}
    data["presse_releases"].append(r)
    save_db(data); backup_db()
    return {"status": "ok", "release": r}

@app.delete("/api/presse/releases/{rel_id}")
async def delete_presse_release(rel_id: str, user=Depends(require_referent)):
    data = load_db()
    data["presse_releases"] = [r for r in data.get("presse_releases", []) if r["id"] != rel_id]
    save_db(data); backup_db()
    return {"status": "ok"}

@app.get("/api/presse/couvertures")
async def list_presse_couvertures(user=Depends(require_auth)):
    data = load_db()
    return data.get("presse_couvertures", [])

@app.post("/api/presse/couvertures")
async def create_presse_couverture(req: PresseCouvertureCreate, user=Depends(require_referent)):
    data = load_db()
    if "presse_couvertures" not in data:
        data["presse_couvertures"] = []
    c = {"id": f"cov-{secrets.token_hex(8)}", **req.dict(), "cree_le": now_iso()}
    data["presse_couvertures"].append(c)
    save_db(data); backup_db()
    return {"status": "ok", "couverture": c}

@app.delete("/api/presse/couvertures/{cov_id}")
async def delete_presse_couverture(cov_id: str, user=Depends(require_referent)):
    data = load_db()
    data["presse_couvertures"] = [c for c in data.get("presse_couvertures", []) if c["id"] != cov_id]
    save_db(data); backup_db()
    return {"status": "ok"}


# ============ F15: ESPACE MEMBRE SELF-SERVICE ============
@app.get("/api/mon-profil")
async def get_mon_profil(user=Depends(require_auth)):
    data = load_db()
    cid = user.get("contact_id", "")
    if not cid:
        raise HTTPException(status_code=404, detail="Aucun contact associe a ce compte")
    for c in data.get("contacts", []):
        if c["id"] == cid:
            # Also return cotisation status
            cots = [ct for ct in data.get("cotisations", []) if ct.get("contact_id") == cid]
            events = data.get("evenements", [])
            my_events = []
            for e in events:
                pres = e.get("presence", {}).get(cid, "")
                if pres:
                    my_events.append({"id": e["id"], "titre": e.get("titre",""), "date": e.get("date",""), "presence": pres})
            return {
                "contact": c,
                "cotisations": cots,
                "events_inscrits": my_events
            }
    raise HTTPException(status_code=404, detail="Contact non trouve")

@app.put("/api/mon-profil")
async def update_mon_profil(req: MembreProfilUpdate, user=Depends(require_auth)):
    data = load_db()
    cid = user.get("contact_id", "")
    if not cid:
        raise HTTPException(status_code=404, detail="Aucun contact associe")
    for c in data.get("contacts", []):
        if c["id"] == cid:
            changes = []
            if req.telephone is not None and c.get("telephone") != req.telephone:
                changes.append(f"telephone: {c.get('telephone','')} -> {req.telephone}")
                c["telephone"] = req.telephone
            if req.email is not None and c.get("email") != req.email:
                changes.append(f"email modifie")
                c["email"] = req.email
            if req.ville is not None:
                c["ville"] = req.ville
                changes.append("ville modifiee")
            if req.code_postal is not None:
                c["code_postal"] = req.code_postal
                changes.append("code postal modifie")
            if changes:
                add_history(c, user["username"], "modification_self", " | ".join(changes))
                save_db(data); backup_db()
            return {"status": "ok", "contact": c}
    raise HTTPException(status_code=404, detail="Contact non trouve")


# ============ STARTUP ============
@app.on_event("startup")
async def startup():
    migrate_plaintext_passwords()
    validate_db_integrity()
    # Demarrer le thread de rappel automatique J-2
    t = threading.Thread(target=_reminder_check_loop, daemon=True)
    t.start()
    print(f"[CRM Romy] v{VERSION} demarre sur {HOST}:{PORT}")
    print(f"[CRM Romy] Base: {DB_PATH}")
    print(f"[CRM Romy] Contacts: {len(load_db().get('contacts', []))}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)