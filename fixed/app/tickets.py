from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import login_required, current_user
from .models import db, Ticket, AuditLog
from .auth import log_action
from datetime import datetime
import bleach
import re

tickets_bp = Blueprint("tickets", __name__)

ALLOWED_SEVERITIES = {"LOW", "MED", "HIGH"}
ALLOWED_STATUSES = {"OPEN", "IN_PROGRESS", "RESOLVED"}

# ─── Helper autorizare ────────────────────────────────────────────────────────
def authorize_ticket(ticket, require_ownership=False):
    """Verifica daca userul curent are acces la ticket. Returneaza 403 daca nu."""
    if current_user.role == "manager":
        return  # manager vede tot
    if ticket.owner_id != current_user.id:
        # FIX #1 (IDOR): loghează tentativa si returneaza 403
        log_action("UNAUTHORIZED_ACCESS", resource_type="ticket",
                   resource_id=str(ticket.id),
                   message=f"User {current_user.id} attempted to access ticket {ticket.id}")
        abort(403)

def sanitize_html(text):
    """FIX #3 (XSS): elimina orice HTML din input. Pastreaza doar text plain."""
    return bleach.clean(text, tags=[], strip=True)

# ─────────────────────────────────────────────────────────────────────────────
@tickets_bp.route("/tickets/<ticket_id>")
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    # FIX #1: verificare acces obligatorie
    authorize_ticket(ticket)
    log_action("TICKET_VIEW", resource_type="ticket", resource_id=str(ticket_id))
    return render_template("tickets/view.html", ticket=ticket)

@tickets_bp.route("/tickets")
@login_required
def list_tickets():
    if current_user.role == "manager":
        tickets = Ticket.query.order_by(Ticket.created_at.desc()).all()
    else:
        tickets = Ticket.query.filter_by(owner_id=current_user.id).order_by(Ticket.created_at.desc()).all()
    return render_template("tickets/list.html", tickets=tickets)

@tickets_bp.route("/tickets/new", methods=["GET", "POST"])
@login_required
def create_ticket():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "LOW").upper()

        # FIX: validare input server-side
        if not title or len(title) > 200:
            flash("Titlu invalid (1-200 caractere).")
            return redirect(url_for("tickets.create_ticket"))
        if severity not in ALLOWED_SEVERITIES:
            flash("Severitate invalida.")
            return redirect(url_for("tickets.create_ticket"))

        # FIX #3 (XSS): sanitizare descriere - strip HTML
        clean_description = sanitize_html(description)

        ticket = Ticket(
            title=sanitize_html(title),
            description=clean_description,
            severity=severity,
            status="OPEN",
            owner_id=current_user.id
        )
        db.session.add(ticket)
        db.session.commit()
        log_action("TICKET_CREATE", resource_type="ticket", resource_id=str(ticket.id))
        flash("Tichet creat cu succes.")
        return redirect(url_for("tickets.list_tickets"))
    return render_template("tickets/create.html")

@tickets_bp.route("/tickets/<ticket_id>/edit", methods=["GET", "POST"])
@login_required
def edit_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    # FIX #1: verificare acces
    authorize_ticket(ticket)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", ticket.severity).upper()
        status = request.form.get("status", ticket.status).upper()

        # FIX: validare valori permise
        if severity not in ALLOWED_SEVERITIES:
            flash("Severitate invalida.")
            return redirect(url_for("tickets.edit_ticket", ticket_id=ticket_id))
        if status not in ALLOWED_STATUSES:
            flash("Status invalid.")
            return redirect(url_for("tickets.edit_ticket", ticket_id=ticket_id))
        if not title or len(title) > 200:
            flash("Titlu invalid.")
            return redirect(url_for("tickets.edit_ticket", ticket_id=ticket_id))

        # FIX #3: sanitizare
        ticket.title = sanitize_html(title)
        ticket.description = sanitize_html(description)
        ticket.severity = severity
        ticket.status = status
        ticket.updated_at = datetime.utcnow()
        db.session.commit()
        log_action("TICKET_UPDATE", resource_type="ticket", resource_id=str(ticket_id))
        flash("Tichet actualizat.")
        return redirect(url_for("tickets.view_ticket", ticket_id=ticket_id))
    return render_template("tickets/edit.html", ticket=ticket)

# FIX #4A (CSRF): Flask-WTF verifica automat token CSRF pentru toate POST-urile
@tickets_bp.route("/tickets/<ticket_id>/status", methods=["POST"])
@login_required
def change_status(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    # FIX #1: verificare acces
    authorize_ticket(ticket)
    new_status = request.form.get("status", "").upper()
    # FIX: validare valori permise
    if new_status not in ALLOWED_STATUSES:
        flash("Status invalid.")
        return redirect(url_for("tickets.view_ticket", ticket_id=ticket_id))
    ticket.status = new_status
    db.session.commit()
    log_action("TICKET_STATUS_CHANGE", resource_type="ticket", resource_id=str(ticket_id),
               message=f"Status -> {new_status}")
    flash(f"Status schimbat în {new_status}.")
    return redirect(url_for("tickets.view_ticket", ticket_id=ticket_id))

@tickets_bp.route("/tickets/<ticket_id>/delete", methods=["POST"])
@login_required
def delete_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    # FIX #1: doar manager poate sterge
    if current_user.role != "manager":
        log_action("UNAUTHORIZED_ACCESS", resource_type="ticket",
                   resource_id=str(ticket_id), message="Delete attempt by non-manager")
        abort(403)
    db.session.delete(ticket)
    db.session.commit()
    log_action("TICKET_DELETE", resource_type="ticket", resource_id=str(ticket_id))
    flash("Tichet șters.")
    return redirect(url_for("tickets.list_tickets"))

# ─────────────────────────────────────────────────────────────────────────────
# FIX #2 (SQL Injection): query parametrizat prin SQLAlchemy ORM
# ─────────────────────────────────────────────────────────────────────────────
@tickets_bp.route("/tickets/search")
@login_required
def search_tickets():
    query = request.args.get("q", "").strip()

    # FIX: validare input (lungime, caractere)
    if len(query) > 100:
        flash("Termenul de căutare este prea lung.")
        return render_template("tickets/search.html", tickets=[], query=query)

    try:
        # FIX #2: ORM parametrizat - nu exista concatenare SQL
        search_term = f"%{query}%"
        base_query = Ticket.query.filter(
            db.or_(
                Ticket.title.ilike(search_term),
                Ticket.description.ilike(search_term)
            )
        )
        # FIX #1: analyst vede doar propriile tichete si in search
        if current_user.role != "manager":
            base_query = base_query.filter_by(owner_id=current_user.id)

        tickets = base_query.limit(50).all()  # limita rezultate
    except Exception as e:
        # FIX #5: eroarea NU e trimisa clientului
        import logging
        logging.error(f"Search error: {e}")
        flash("A apărut o eroare la căutare. Încearcă din nou.")
        return render_template("tickets/search.html", tickets=[], query=query)

    log_action("SEARCH", resource_type="search", message=f"Search: {query[:50]}")
    return render_template("tickets/search.html", tickets=tickets, query=query)

# ─────────────────────────────────────────────────────────────────────────────
# FIX #5: handler global erori - mesaje generice catre client
# ─────────────────────────────────────────────────────────────────────────────
@tickets_bp.app_errorhandler(403)
def forbidden(e):
    return render_template("errors/403.html"), 403

@tickets_bp.app_errorhandler(404)
def not_found(e):
    return render_template("errors/404.html"), 404

@tickets_bp.app_errorhandler(500)
def server_error(e):
    import logging
    logging.error(f"500 error: {e}")
    return render_template("errors/500.html"), 500

@tickets_bp.route("/audit")
@login_required
def audit_log():
    # FIX #1: doar manager poate vedea audit log
    if current_user.role != "manager":
        abort(403)
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(500).all()
    return render_template("tickets/audit.html", logs=logs)
