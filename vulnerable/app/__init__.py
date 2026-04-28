from flask import Flask
from flask_login import LoginManager
from .models import db, User
from config import Config

login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    from .auth import auth_bp
    from .tickets import tickets_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(tickets_bp)

    with app.app_context():
        db.create_all()

    return app

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
