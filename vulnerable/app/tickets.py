from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from .models import db, Ticket, AuditLog
from .auth import log_action
from datetime import datetime

tickets_bp = Blueprint("tickets", __name__)

# ─────────────────────────────────────────────
# VULNERABILITATE #1 (IDOR): nu se verifica owner_id sau rol
# Orice user autentificat poate accesa orice ticket modificand ID-ul din URL
# ─────────────────────────────────────────────
@tickets_bp.route("/tickets/<int:ticket_id>")
@login_required
def view_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    # LIPSA verificare: if ticket.owner_id != current_user.id and current_user.role != "manager": abort(403)
    log_action("TICKET_VIEW", resource_type="ticket", resource_id=str(ticket_id))
    return render_template("tickets/view.html", ticket=ticket)

@tickets_bp.route("/tickets")
@login_required
def list_tickets():
    if current_user.role == "manager":
        tickets = Ticket.query.all()
    else:
        tickets = Ticket.query.filter_by(owner_id=current_user.id).all()
    return render_template("tickets/list.html", tickets=tickets)

@tickets_bp.route("/tickets/new", methods=["GET", "POST"])
@login_required
def create_ticket():
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        severity = request.form.get("severity", "LOW")

        # VULNERABILITATE #3 (XSS Stored): descrierea NU e sanitizata
        # Va fi afisata direct ca HTML in template cu |safe
        ticket = Ticket(
            title=title,
            description=description,  # input brut, neescapat
            severity=severity,
            status="OPEN",
            owner_id=current_user.id
        )
        db.session.add(ticket)
        db.session.commit()
        log_action("TICKET_CREATE", resource_type="ticket", resource_id=str(ticket.id))
        flash("Ticket creat.")
        return redirect(url_for("tickets.list_tickets"))
    return render_template("tickets/create.html")

# ─────────────────────────────────────────────
# VULNERABILITATE #1 (IDOR): orice user poate edita orice ticket
# VULNERABILITATE #4A (CSRF): nu se verifica token CSRF
# ─────────────────────────────────────────────
@tickets_bp.route("/tickets/<int:ticket_id>/edit", methods=["GET", "POST"])
@login_required
def edit_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    # LIPSA verificare acces!
    if request.method == "POST":
        ticket.title = request.form.get("title")
        ticket.description = request.form.get("description")
        ticket.severity = request.form.get("severity", ticket.severity)
        ticket.status = request.form.get("status", ticket.status)
        ticket.updated_at = datetime.utcnow()
        db.session.commit()
        log_action("TICKET_UPDATE", resource_type="ticket", resource_id=str(ticket_id))
        flash("Ticket actualizat.")
        return redirect(url_for("tickets.view_ticket", ticket_id=ticket_id))
    return render_template("tickets/edit.html", ticket=ticket)

# ─────────────────────────────────────────────
# VULNERABILITATE #4A (CSRF): schimbare status fara token CSRF
# Poate fi declansat dintr-o pagina externa
# ─────────────────────────────────────────────
@tickets_bp.route("/tickets/<int:ticket_id>/status", methods=["POST"])
@login_required
def change_status(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    # LIPSA: verificare CSRF token, verificare acces
    new_status = request.form.get("status")
    ticket.status = new_status
    db.session.commit()
    log_action("TICKET_STATUS_CHANGE", resource_type="ticket", resource_id=str(ticket_id),
               message=f"Status -> {new_status}")
    flash(f"Status schimbat in {new_status}.")
    return redirect(url_for("tickets.view_ticket", ticket_id=ticket_id))

@tickets_bp.route("/tickets/<int:ticket_id>/delete", methods=["POST"])
@login_required
def delete_ticket(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    # LIPSA verificare rol manager!
    db.session.delete(ticket)
    db.session.commit()
    log_action("TICKET_DELETE", resource_type="ticket", resource_id=str(ticket_id))
    flash("Ticket sters.")
    return redirect(url_for("tickets.list_tickets"))

# ─────────────────────────────────────────────
# VULNERABILITATE #2 (SQL Injection): concatenare string in query
# ─────────────────────────────────────────────
@tickets_bp.route("/tickets/search")
@login_required
def search_tickets():
    query = request.args.get("q", "")
    try:
        # VULNERABILITATE: concatenare directa a input-ului utilizatorului in SQL
        # Input malitios: ' OR '1'='1  -> returneaza toate tichetele
        # Input malitios: ' UNION SELECT id,email,password,email,email,datetime('now'),datetime('now') FROM users --
        sql = f"SELECT * FROM tickets WHERE title LIKE '%{query}%' OR description LIKE '%{query}%'"
        result = db.session.execute(db.text(sql))
        tickets = result.fetchall()
    except Exception as e:
        # VULNERABILITATE #5 (Info Disclosure): eroarea DB e trimisa clientului
        return f"<pre>Eroare DB: {str(e)}\nQuery: {sql}</pre>", 500

    log_action("SEARCH", resource_type="search", message=f"Search: {query}")
    return render_template("tickets/search.html", tickets=tickets, query=query)

@tickets_bp.route("/audit")
@login_required
def audit_log():
    if current_user.role != "manager":
        flash("Acces interzis.")
        return redirect(url_for("tickets.list_tickets"))
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).all()
    return render_template("tickets/audit.html", logs=logs)
