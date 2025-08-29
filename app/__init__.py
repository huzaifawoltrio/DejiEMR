# huzaifawoltrio/dejiemr/DejiEMR-new-patient-profile/app/__init__.py
import logging
import os
from logging.handlers import RotatingFileHandler
from flask import Flask
from config import Config
from .extensions import db, migrate, bcrypt, cors, jwt, limiter, socketio
from .commands import create_roles, create_permissions, assign_permissions_to_role, init_db_command
from .models import user_models, system_models, patient_profile_models, appointment_models, chat_models
from .api import api_bp
from .utils.error_handlers import register_error_handlers

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure the logs directory exists
    if not os.path.exists('logs'):
        os.mkdir('logs')

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    cors.init_app(app, resources={r"/api/*": {"origins": "*"}})
    jwt.init_app(app)
    limiter.init_app(app)
    socketio.init_app(app)

    # Register blueprints
    app.register_blueprint(api_bp, url_prefix='/api')

    # Register error handlers
    register_error_handlers(app)

    # Add CLI commands
    app.cli.add_command(create_roles)
    app.cli.add_command(create_permissions)
    app.cli.add_command(assign_permissions_to_role)
    app.cli.add_command(init_db_command)   

    # Configure logging (now outside the debug check)
    # General application logger
    handler = RotatingFileHandler('logs/emr_app.log', maxBytes=10240, backupCount=10)
    handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    
    # Dedicated audit logger
    audit_handler = RotatingFileHandler('logs/emr_audit.log', maxBytes=10240, backupCount=10)
    audit_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s'
    ))
    audit_handler.setLevel(logging.INFO)
    
    audit_logger = logging.getLogger('audit')
    audit_logger.addHandler(audit_handler)
    audit_logger.setLevel(logging.INFO)
    app.audit_logger = audit_logger

    if not app.debug and not app.testing:
        app.logger.info('EMR startup')

    return app
