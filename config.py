# /config.py
import os
import secrets
from datetime import timedelta
import logging
from logging.handlers import RotatingFileHandler

class Config:
    """HIPAA-compliant configuration settings"""
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or secrets.token_hex(32)

    # Server configuration - Remove SERVER_NAME to avoid session issues
    # SERVER_NAME should only be set in production with a real domain
    # SERVER_NAME = os.environ.get('SERVER_NAME', 'localhost:5000')  # REMOVE THIS LINE

    # Session configuration - CRITICAL for OAuth
    SESSION_TYPE = 'filesystem'  # Use filesystem for better persistence
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)  # Sessions last 24 hours
    SESSION_COOKIE_NAME = 'deji_emr_session'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'  # Changed from 'Strict' to 'Lax' for OAuth
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    
    # Add session file directory
    SESSION_FILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flask_session')
    SESSION_FILE_THRESHOLD = 500
    SESSION_FILE_MODE = 384  # 0600 in octal
    
    # Encryption key
    EMR_ENCRYPTION_KEY = os.environ.get('EMR_ENCRYPTION_KEY')

    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=1)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://postgres:postgres@localhost:5432/deji-new-emr'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL') or 'memory://'
    
    # CORS
    ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')
    
    # Cloudinary Configuration
    CLOUDINARY_CLOUD_NAME = os.environ.get('CLOUDINARY_CLOUD_NAME')
    CLOUDINARY_API_KEY = os.environ.get('CLOUDINARY_API_KEY')
    CLOUDINARY_API_SECRET = os.environ.get('CLOUDINARY_API_SECRET')
    
    # Google OAuth Configuration
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')

    @staticmethod
    def init_app(app):
        """Initialize application-specific configuration"""
        # Create logs directory if it doesn't exist
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        # Create session directory if using filesystem sessions
        session_dir = app.config.get('SESSION_FILE_DIR')
        if session_dir and not os.path.exists(session_dir):
            os.makedirs(session_dir, mode=0o700)
        
        # Configure main application logging
        if not app.debug and not app.testing:
            # Production logging setup with rotation
            file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240000, backupCount=10)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.INFO)
            app.logger.addHandler(file_handler)
            app.logger.setLevel(logging.INFO)
            app.logger.info('EMR application startup')
        
        # Set up HIPAA audit logger
        audit_logger = logging.getLogger('HIPAA_AUDIT')
        if not audit_logger.handlers:
            # Use rotating file handler for audit logs
            audit_handler = RotatingFileHandler('logs/hipaa_audit.log', maxBytes=10240000, backupCount=20)
            audit_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(message)s'
            ))
            audit_logger.addHandler(audit_handler)
            audit_logger.setLevel(logging.INFO)
            audit_logger.propagate = False  # Prevent duplicate logs
        
        app.audit_logger = audit_logger

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or 'postgresql://postgres:postgres@localhost:5432/deji-new-emr-dev'
    
    # Override security settings for development
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = 'Lax'  # Allow OAuth redirects in dev
    
    @staticmethod
    def init_app(app):
        Config.init_app(app)
        
        # Development-specific logging (less verbose)
        if not app.logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s'
            ))
            app.logger.addHandler(console_handler)
            app.logger.setLevel(logging.DEBUG)

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=1)  # Short expiry for testing
    
    # Disable security features for testing
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    @staticmethod
    def init_app(app):
        Config.init_app(app)

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    
    # In production, use more secure session settings
    SESSION_COOKIE_SECURE = True  # Requires HTTPS
    SESSION_COOKIE_SAMESITE = 'Lax'  # Still need Lax for OAuth
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Production-specific initialization
        app.logger.info('EMR Production application startup')
        
        # Additional production security validation
        if not os.environ.get('EMR_ENCRYPTION_KEY'):
            app.logger.error('EMR_ENCRYPTION_KEY not set in production!')
            raise ValueError('EMR_ENCRYPTION_KEY must be set in production')
        
        if not os.environ.get('JWT_SECRET_KEY'):
            app.logger.error('JWT_SECRET_KEY not set in production!')
            raise ValueError('JWT_SECRET_KEY must be set in production')
        
        if not os.environ.get('GOOGLE_CLIENT_ID') or not os.environ.get('GOOGLE_CLIENT_SECRET'):
            app.logger.warning('Google OAuth credentials not set - Google Calendar integration will not work')

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}