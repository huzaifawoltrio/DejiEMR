from flask import Flask
from app.extensions import db, bcrypt, migrate, jwt, limiter, cors, socketio
from app.utils.encryption_util import encryptor
from app.utils.cloudinary_util import cloudinary_manager
from app.utils.error_handlers import register_error_handlers
from app.commands import register_commands
from flask_cors import CORS
import os
from config import Config
from app.models.patient_document_models import PatientDocument

# Don't import Flask-Session - use Flask's built-in sessions instead

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'mysupersecretkey') 
    
    # Use Flask's built-in sessions instead of Flask-Session
    # This avoids the eventlet/filesystem conflicts on Windows
    app.config['SESSION_COOKIE_NAME'] = 'localhost:5000'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Allow OAuth redirects
    app.config['SESSION_COOKIE_SECURE'] = False  # Set to True with HTTPS
    app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 hours in seconds
    
    # Don't initialize Flask-Session at all
    # Flask's built-in sessions will be used automatically
    
    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)
    cors.init_app(app, origins=app.config['ALLOWED_ORIGINS'])
    
    # Initialize SocketIO with threading (no eventlet)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')
    
    # Initialize custom utilities
    encryptor.init_app(app)
    cloudinary_manager.init_app(app)
    
    # Initialize app with config
    Config.init_app(app)
    
    CORS(app, 
         origins=[
             "http://localhost:3000",  # Next.js development server
             "http://127.0.0.1:3000",
             "https://yourdomain.com"  # Add your production domain
         ],
         supports_credentials=True,  # Important for sessions
         allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    )
    
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