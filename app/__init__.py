# /app/__init__.py
from flask import Flask
from app.extensions import db, bcrypt, migrate, jwt, limiter, cors, socketio
from app.utils.encryption_util import encryptor
from app.utils.cloudinary_util import cloudinary_manager
from app.utils.error_handlers import register_error_handlers
from app.commands import register_commands
from config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)
    cors.init_app(app, origins=app.config['ALLOWED_ORIGINS'])
    # Initialize SocketIO without specifying async_mode here
    # It will be handled by the runner in run.py
    socketio.init_app(app, cors_allowed_origins="*")

    
    # Initialize custom utilities
    encryptor.init_app(app)
    cloudinary_manager.init_app(app)
    
    # Initialize app with config
    Config.init_app(app)
    
    # Register blueprints
    from app.api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')

    from app.socket_handlers import chat_handler

    
    # Register error handlers and commands  
    register_error_handlers(app)
    register_commands(app)
    
    # JWT token blacklist checker
    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        from app.models.system_models import RevokedToken
        jti = jwt_payload['jti']
        return RevokedToken.query.filter_by(jti=jti).first() is not None
    
    return app
