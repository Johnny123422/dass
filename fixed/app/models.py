from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import uuid

db = SQLAlchemy()

def gen_uuid():
    return str(uuid.uuid4())

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    email = db.Column(db.String(254), unique=True, nullable=False)
    # FIX #6: stocare hash, nu parola in clear
    password_hash = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(20), nullable=False, default="analyst")
    # FIX #6: suport lockout dupa brute-force
    is_locked = db.Column(db.Boolean, default=False, nullable=False)
    failed_logins = db.Column(db.Integer, default=0, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tickets = db.relationship("Ticket", backref="owner", lazy=True)

class Ticket(db.Model):
    __tablename__ = "tickets"
    # FIX #1 (IDOR): UUID in loc de integer secvential
    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(10), nullable=False, default="LOW")
    status = db.Column(db.String(20), nullable=False, default="OPEN")
    owner_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.String(36), primary_key=True, default=gen_uuid)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    resource_type = db.Column(db.String(30), nullable=False)
    resource_id = db.Column(db.String(36), nullable=True)
    message = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
