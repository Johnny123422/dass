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
    # VULNERABILITATE #6: parola stocata in plain text
    password = db.Column(db.Text, nullable=False)
    role = db.Column(db.String(20), nullable=False, default="analyst")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    tickets = db.relationship("Ticket", backref="owner", lazy=True)

class Ticket(db.Model):
    __tablename__ = "tickets"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # INTEGER sequential - mai usor pentru IDOR
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
