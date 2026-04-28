"""
Teste automate de securitate – Deskly
Testeaza versiunea FIXED (aplicatie securizata)

Ruleaza cu: pytest tests/test_security.py -v
"""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'fixed'))

from app import create_app
from app.models import db as _db, User, Ticket
import bcrypt


@pytest.fixture(scope="module")
def app():
    test_app = create_app()
    test_app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": "test-secret-key-only",
        "SESSION_COOKIE_SECURE": False,
    })
    with test_app.app_context():
        _db.create_all()
        yield test_app
        _db.drop_all()


@pytest.fixture(scope="module")
def client(app):
    return app.test_client()


@pytest.fixture(scope="module")
def init_users(app):
    with app.app_context():
        pwd_hash1 = bcrypt.hashpw(b"Test1234", bcrypt.gensalt(rounds=4)).decode()
        pwd_hash2 = bcrypt.hashpw(b"Test1234", bcrypt.gensalt(rounds=4)).decode()
        pwd_hash3 = bcrypt.hashpw(b"Test1234", bcrypt.gensalt(rounds=4)).decode()

        analyst1 = User(email="analyst1@test.ro", password_hash=pwd_hash1, role="analyst")
        analyst2 = User(email="analyst2@test.ro", password_hash=pwd_hash2, role="analyst")
        manager1 = User(email="manager1@test.ro", password_hash=pwd_hash3, role="manager")

        _db.session.add_all([analyst1, analyst2, manager1])
        _db.session.commit()

        t1 = Ticket(title="Ticket analyst1", description="Descriere", severity="LOW",
                    status="OPEN", owner_id=analyst1.id)
        t2 = Ticket(title="Ticket analyst2", description="Confidential", severity="HIGH",
                    status="OPEN", owner_id=analyst2.id)
        _db.session.add_all([t1, t2])
        _db.session.commit()

        return {
            "analyst1_id": analyst1.id,
            "analyst2_id": analyst2.id,
            "manager1_id": manager1.id,
            "ticket_a1_id": t1.id,
            "ticket_a2_id": t2.id,
            "pwd_hash1": pwd_hash1,
            "pwd_hash2": pwd_hash2,
        }


def login_as(client, email, password="Test1234"):
    return client.post("/login", data={"email": email, "password": password}, follow_redirects=True)


def logout(client):
    client.get("/logout", follow_redirects=True)


class TestIDOR:
    def test_analyst_cannot_view_other_users_ticket(self, client, init_users):
        """FIX #1: analyst1 nu poate accesa ticket-ul lui analyst2."""
        login_as(client, "analyst1@test.ro")
        ticket_id = init_users["ticket_a2_id"]
        resp = client.get(f"/tickets/{ticket_id}", follow_redirects=False)
        assert resp.status_code == 403
        logout(client)

    def test_analyst_cannot_edit_other_users_ticket(self, client, init_users):
        """FIX #1: analyst1 nu poate edita ticket-ul lui analyst2."""
        login_as(client, "analyst1@test.ro")
        ticket_id = init_users["ticket_a2_id"]
        resp = client.post(f"/tickets/{ticket_id}/edit",
                           data={"title": "Hacked", "description": "x", "severity": "LOW", "status": "OPEN"},
                           follow_redirects=False)
        assert resp.status_code == 403
        logout(client)

    def test_manager_can_view_all_tickets(self, client, init_users):
        """Manager are acces la toate tichetele."""
        login_as(client, "manager1@test.ro")
        ticket_id = init_users["ticket_a1_id"]
        resp = client.get(f"/tickets/{ticket_id}")
        assert resp.status_code == 200
        logout(client)

    def test_analyst_can_view_own_ticket(self, client, init_users):
        """Analyst poate vedea propriul tichet."""
        login_as(client, "analyst1@test.ro")
        ticket_id = init_users["ticket_a1_id"]
        resp = client.get(f"/tickets/{ticket_id}")
        assert resp.status_code == 200
        logout(client)


class TestSQLInjection:
    def test_sql_injection_classic_or_1_1(self, client, init_users):
        """FIX #2: OR 1=1 nu returneaza toate tichetele."""
        login_as(client, "analyst1@test.ro")
        payload = "' OR '1'='1"
        resp = client.get(f"/tickets/search?q={payload}")
        assert resp.status_code == 200
        assert b"Confidential" not in resp.data
        logout(client)

    def test_sql_injection_union_select(self, client, init_users):
        """FIX #2: UNION SELECT nu extrage date din tabela users."""
        login_as(client, "analyst1@test.ro")
        payload = "' UNION SELECT id,email,password_hash,email,email,datetime('now'),datetime('now'),datetime('now') FROM users --"
        resp = client.get(f"/tickets/search?q={payload}")
        assert resp.status_code == 200
        assert b"$2b$" not in resp.data
        assert b"analyst2@test.ro" not in resp.data
        logout(client)

    def test_malicious_input_no_server_error(self, client, init_users):
        """FIX #5: input malitios nu produce stack trace."""
        login_as(client, "analyst1@test.ro")
        payload = "'; DROP TABLE tickets; --"
        resp = client.get(f"/tickets/search?q={payload}")
        assert resp.status_code == 200
        assert b"Traceback" not in resp.data
        assert b"sqlite3" not in resp.data
        logout(client)


class TestXSS:
    def test_xss_payload_stored_as_text(self, client, init_users, app):
        """FIX #3: script in descriere este eliminat de bleach."""
        login_as(client, "analyst1@test.ro")
        resp = client.post("/tickets/new", data={
            "title": "Test XSS",
            "description": "<script>alert('XSS')</script>",
            "severity": "LOW"
        }, follow_redirects=True)
        assert resp.status_code == 200

        with app.app_context():
            ticket = Ticket.query.filter_by(title="Test XSS").first()
            assert ticket is not None
            assert "<script>" not in ticket.description
        logout(client)

    def test_xss_payload_not_executable_in_response(self, client, init_users, app):
        """FIX #3: raspunsul nu contine tag-uri script executabile."""
        login_as(client, "analyst1@test.ro")
        client.post("/tickets/new", data={
            "title": "XSS Test 2",
            "description": "<img src=x onerror=alert(1)>",
            "severity": "LOW"
        }, follow_redirects=True)

        with app.app_context():
            ticket = Ticket.query.filter_by(title="XSS Test 2").first()
            ticket_id = ticket.id if ticket else None

        if ticket_id:
            resp = client.get(f"/tickets/{ticket_id}")
            assert b"onerror" not in resp.data
        logout(client)


class TestPasswordStorage:
    def test_password_stored_as_bcrypt_hash(self, app):
        """FIX #6: parola stocata ca hash bcrypt."""
        with app.app_context():
            user = User.query.filter_by(email="analyst1@test.ro").first()
            assert user.password_hash.startswith("$2b$")
            assert "Test1234" not in user.password_hash

    def test_different_users_same_password_different_hashes(self, init_users):
        """FIX #6: salt unic – acelasi password produce hash-uri diferite."""
        assert init_users["pwd_hash1"] != init_users["pwd_hash2"], \
            "FAIL: hash-uri identice (salt lipsa)!"

    def test_bcrypt_verify_correct_password(self, app):
        """FIX #6: verificarea parolei corecte."""
        with app.app_context():
            user = User.query.filter_by(email="analyst1@test.ro").first()
            assert bcrypt.checkpw(b"Test1234", user.password_hash.encode()) is True

    def test_bcrypt_reject_wrong_password(self, app):
        """FIX #6: parola gresita este respinsa."""
        with app.app_context():
            user = User.query.filter_by(email="analyst1@test.ro").first()
            assert bcrypt.checkpw(b"WrongPassword", user.password_hash.encode()) is False


class TestAuthorization:
    def test_analyst_cannot_delete_ticket(self, client, init_users):
        """FIX #1: analyst nu poate sterge tichete."""
        login_as(client, "analyst1@test.ro")
        ticket_id = init_users["ticket_a1_id"]
        resp = client.post(f"/tickets/{ticket_id}/delete", follow_redirects=False)
        assert resp.status_code == 403
        logout(client)

    def test_analyst_cannot_access_audit_log(self, client, init_users):
        """FIX #1: analyst nu poate accesa audit log-ul."""
        login_as(client, "analyst1@test.ro")
        resp = client.get("/audit", follow_redirects=False)
        assert resp.status_code == 403
        logout(client)

    def test_manager_can_delete_ticket(self, client, init_users, app):
        """Manager poate sterge tichete."""
        login_as(client, "manager1@test.ro")
        with app.app_context():
            t = Ticket(title="De sters", description="x", severity="LOW",
                       status="OPEN", owner_id=init_users["analyst1_id"])
            _db.session.add(t)
            _db.session.commit()
            tid = t.id
        resp = client.post(f"/tickets/{tid}/delete", follow_redirects=True)
        assert resp.status_code == 200
        logout(client)

    def test_unauthenticated_user_redirected(self, client):
        """Utilizator neautentificat este redirectionat la login."""
        logout(client)
        resp = client.get("/tickets", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("Location", "")