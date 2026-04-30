# Deskly – Build, Hack & Secure
**Proiect #1 – Hack your own app before someone else does**
Curs: Dezvoltarea Aplicațiilor Software Securizate – FMI, Unibuc

---

## Structura proiectului

```
deskly/
├── vulnerable/          # Versiunea cu vulnerabilități (branch: vulnerable)
│   ├── app/
│   │   ├── __init__.py
│   │   ├── models.py    # Parole plain text, ID integer secvential
│   │   ├── auth.py      # Login fara rate limiting, mesaje verbose
│   │   ├── tickets.py   # IDOR, SQLi, XSS, CSRF, lipsa autorizare
│   │   └── templates/
│   ├── config.py        # SECRET_KEY slab, cookie flags lipsa
│   ├── requirements.txt
│   └── run.py           # debug=True
│
├── fixed/               # Versiunea securizata (branch: fixed)
│   ├── app/
│   │   ├── __init__.py  # Flask-WTF CSRF protection
│   │   ├── models.py    # password_hash (bcrypt), UUID ticket IDs
│   │   ├── auth.py      # bcrypt, rate limiting, lockout, mesaje generice
│   │   ├── tickets.py   # RBAC, query parametrizat, output escaping, 403 handler
│   │   └── templates/
│   ├── config.py        # Cookie flags, expirare corecta, secret random
│   ├── requirements.txt
│   └── run.py           # debug=False
│
├── tests/
│   └── test_security.py # 14+ teste automate de securitate
│
└── poc/
    ├── poc_commands.sh  # Comenzi demonstrare atac (curl)
    └── csrf_attack.html # Pagina externa malitioasa (demo CSRF)
```

---

## Setup si rulare

### 1. Versiunea VULNERABILA

```bash
cd vulnerable
python -m venv venv
source venv/bin/activate   # Linux/Mac
# venv\Scripts\activate    # Windows
pip install -r requirements.txt
python run.py
# Acceseaza: http://localhost:5000
```

### 2. Versiunea SECURIZATA

```bash
cd fixed
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
# Acceseaza: http://localhost:5001
```

### 3. Rulare teste

```bash
cd ..   # din radacina proiectului
pip install pytest
pytest tests/test_security.py -v
```

---

## Vulnerabilitati implementate intentionat (versiunea vulnerabila)

| # | OWASP | Locatie | Descriere |
|---|-------|---------|-----------|
| 1 | Broken Access Control (IDOR) | `tickets.py` – view/edit/delete | Nicio verificare owner_id sau rol |
| 2 | Injection (SQLi) | `tickets.py` – `search_tickets()` | Concatenare string in query SQL |
| 3 | XSS Stored | `templates/tickets/view.html` | Filtrul `\|safe` in Jinja2 |
| 4A | CSRF | `tickets.py` – `change_status()` | Nicio verificare token CSRF |
| 4B | Session Management | `config.py` | Fara HttpOnly, Secure, SameSite |
| 5 | Error & Info Disclosure | `tickets.py` – except block | Stack trace afisat clientului |
| 6 | Password Storage | `models.py` + `auth.py` | Parole stocate plain text |

---

## Fix-uri aplicate (versiunea securizata)

| # | Fix | Implementare |
|---|-----|--------------|
| 1 | RBAC + ownership check | `authorize_ticket()` in `tickets.py`, abort(403) + audit log |
| 2 | Query parametrizat | ORM SQLAlchemy cu `.ilike()` parametrizat |
| 3 | Output escaping | Eliminat `\|safe`, bleach.clean() la input |
| 4A | CSRF token | Flask-WTF `CSRFProtect()` global |
| 4B | Cookie hardening | `HttpOnly=True`, `SameSite=Lax`, expirare 1h |
| 5 | Error handling | Handler global, mesaje generice, detalii in log |
| 6 | Bcrypt + lockout | `bcrypt.hashpw()` cost 12, 5 incercari -> lock |

---

## Utilizatori de test

Creeaza prin `/register`:
- `lupes@gmail.com` / `Parola1234` — rol: Analyst
- `lupes1@gmail.com` / `Parola1234` — rol: Analyst
- `lupes2@gmail.com` / `Parola1234` — rol: Manager
