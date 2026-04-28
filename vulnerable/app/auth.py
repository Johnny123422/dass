from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from .models import db, User, AuditLog
from datetime import datetime

auth_bp = Blueprint("auth", __name__)

def log_action(action, resource_type="auth", resource_id=None, message=None, user_id=None):
    entry = AuditLog(
        user_id=user_id or (current_user.id if not current_user.is_anonymous else None),
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        message=message,
        ip_address=request.remote_addr
    )
    db.session.add(entry)
    db.session.commit()

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role", "analyst")

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash("Email deja existent.")
            return redirect(url_for("auth.register"))

        # VULNERABILITATE #6: parola stocata in plain text, fara hash
        user = User(email=email, password=password, role=role)
        db.session.add(user)
        db.session.commit()
        log_action("REGISTER", user_id=user.id, message=f"User {email} registered")
        flash("Cont creat. Loghează-te.")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # VULNERABILITATE #6: comparatie parola plain text
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
            session.permanent = True
            log_action("LOGIN_SUCCESS", user_id=user.id, message=f"Login: {email}")
            return redirect(url_for("tickets.list_tickets"))
        else:
            # VULNERABILITATE #5: mesaj de eroare verbose + fara rate limiting
            log_action("LOGIN_FAILED", message=f"Failed login for {email}")
            flash(f"Autentificare esuata pentru utilizatorul: {email}. Parola incorecta.")
            return redirect(url_for("auth.login"))

    return render_template("auth/login.html")

@auth_bp.route("/logout")
@login_required
def logout():
    log_action("LOGOUT", message=f"Logout: {current_user.email}")
    logout_user()
    # VULNERABILITATE #4B: sesiunea nu e invalidata complet server-side
    return redirect(url_for("auth.login"))
