from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from .models import db, User, AuditLog
from datetime import datetime, timedelta
import bcrypt
import re

auth_bp = Blueprint("auth", __name__)

# ─── Helper audit ────────────────────────────────────────────────────────────
def log_action(action, resource_type="auth", resource_id=None, message=None, user_id=None):
    uid = user_id or (current_user.id if not current_user.is_anonymous else None)
    entry = AuditLog(
        user_id=uid,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        message=message,
        ip_address=request.remote_addr,
        user_agent=request.headers.get("User-Agent", "")[:200]
    )
    db.session.add(entry)
    db.session.commit()

# ─── Validare parola ──────────────────────────────────────────────────────────
def validate_password(password):
    if len(password) < 8:
        return False, "Parola trebuie să aibă minim 8 caractere."
    if not re.search(r"[A-Z]", password):
        return False, "Parola trebuie să conțină cel puțin o literă mare."
    if not re.search(r"[0-9]", password):
        return False, "Parola trebuie să conțină cel puțin o cifră."
    return True, None

# ─────────────────────────────────────────────────────────────────────────────
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "analyst")

        # FIX: validare role server-side (nu acceptam orice string)
        if role not in ("analyst", "manager"):
            role = "analyst"

        # FIX: validare email
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            flash("Email invalid.")
            return redirect(url_for("auth.register"))

        # FIX #6: validare politica parola
        ok, err = validate_password(password)
        if not ok:
            flash(err)
            return redirect(url_for("auth.register"))

        existing = User.query.filter_by(email=email).first()
        if existing:
            # FIX #5: mesaj generic, nu revela daca exista userul
            flash("A apărut o problemă. Încearcă din nou.")
            return redirect(url_for("auth.register"))

        # FIX #6: hash bcrypt cu cost factor 12
        pwd_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")

        user = User(email=email, password_hash=pwd_hash, role=role)
        db.session.add(user)
        db.session.commit()
        log_action("REGISTER", user_id=user.id, message=f"User {email} registered with role {role}")
        flash("Cont creat cu succes. Te poți autentifica.")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        # FIX #6: verificare lockout
        if user and user.is_locked:
            log_action("LOGIN_FAILED", message=f"Attempt on locked account: {email}")
            # FIX #5: mesaj generic
            flash("Autentificare eșuată. Verifică datele introduse.")
            return redirect(url_for("auth.login"))

        # FIX #6: verificare bcrypt hash
        if user and bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
            # Resetare contor esecuri la login reusit
            user.failed_logins = 0
            user.last_login_at = datetime.utcnow()
            db.session.commit()

            login_user(user)
            session.permanent = True
            log_action("LOGIN_SUCCESS", user_id=user.id, message=f"Successful login: {email}")
            return redirect(url_for("tickets.list_tickets"))
        else:
            # FIX #6: incrementare contor si lockout
            if user:
                user.failed_logins += 1
                if user.failed_logins >= current_app.config.get("MAX_LOGIN_ATTEMPTS", 5):
                    user.is_locked = True
                    log_action("LOGIN_FAILED", user_id=user.id,
                               message=f"Account locked after {user.failed_logins} failed attempts")
                db.session.commit()
            else:
                log_action("LOGIN_FAILED", message=f"Unknown email: {email}")

            # FIX #5: mesaj generic, fara a revela email-ul
            flash("Autentificare eșuată. Verifică datele introduse.")
            return redirect(url_for("auth.login"))

    return render_template("auth/login.html")

@auth_bp.route("/logout")
@login_required
def logout():
    log_action("LOGOUT", message=f"Logout: {current_user.email}")
    # FIX #4B: curatare sesiune la logout
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))
