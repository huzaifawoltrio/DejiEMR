# /app/__init__.py
import os
from flask import Flask, jsonify
from config import Config
from .extensions import db, bcrypt, migrate, jwt, limiter, cors
from .models.system_models import RevokedToken

def create_app(config_class=Config):
    """Application factory"""
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # 1. Ensure JWT_SECRET_KEY is set from the environment variables
    # This reads the key from your .env file
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)
    cors.init_app(app, origins=app.config['ALLOWED_ORIGINS'], supports_credentials=True)
    
    # Initialize logging
    config_class.init_app(app)

    # Register Blueprints
    from .api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    # Register CLI commands
    from .commands import register_commands
    register_commands(app)
    
    # Register error handlers
    from .utils.error_handlers import register_error_handlers
    register_error_handlers(app)

    # JWT Configuration and Callbacks
    configure_jwt(app)
    
    # Register security headers middleware
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response
        
    return app

def configure_jwt(app):
    """JWT callback functions"""
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload['jti']
        token = RevokedToken.query.filter_by(jti=jti).first()
        return token is not None

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({'error': 'Token has expired'}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({'error': 'Invalid token', 'message': str(error)}), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({'error': 'Authorization required'}), 401

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return jsonify({'error': 'Token has been revoked'}), 401
