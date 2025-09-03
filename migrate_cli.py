#!/usr/bin/env python3
"""
CLI script for database migrations that avoids eventlet conflicts.
Use this instead of 'flask db migrate' when you have eventlet in your app.

Usage:
    python migrate_cli.py "Migration message"
"""

import sys
import os
from dotenv import load_dotenv

# Load environment variables first
load_dotenv()

# Set Flask app for CLI commands
os.environ['FLASK_APP'] = 'run.py'

# Import Flask and create app without eventlet
from flask import Flask
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from app.extensions import db

def create_cli_app():
    """Create Flask app specifically for CLI operations without eventlet."""
    app = Flask(__name__)
    
    # Load config
    from config import Config
    app.config.from_object(Config)
    
    # Initialize only necessary extensions
    db.init_app(app)
    migrate = Migrate(app, db)
    
    return app, migrate

def run_migration(message="Auto migration"):
    """Run database migration."""
    app, migrate_obj = create_cli_app()
    
    with app.app_context():
        from flask_migrate import migrate
        try:
            # Import all models so they're registered with SQLAlchemy
            from app.models import user_models, patient_profile_models, system_models, appointment_models, chat_models, google_meet_model
            
            # Run the migration
            migrate(message=message)
            print(f"Migration created successfully: {message}")
            
        except Exception as e:
            print(f"Migration failed: {str(e)}")
            sys.exit(1)

def run_upgrade():
    """Apply migrations to database."""
    app, migrate_obj = create_cli_app()
    
    with app.app_context():
        from flask_migrate import upgrade
        try:
            upgrade()
            print("Database upgraded successfully")
        except Exception as e:
            print(f"Upgrade failed: {str(e)}")
            sys.exit(1)

def run_init():
    """Initialize migration repository."""
    app, migrate_obj = create_cli_app()
    
    with app.app_context():
        from flask_migrate import init
        try:
            init()
            print("Migration repository initialized successfully")
        except Exception as e:
            print(f"Init failed: {str(e)}")
            sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python migrate_cli.py migrate 'Migration message'")
        print("  python migrate_cli.py upgrade")
        print("  python migrate_cli.py init")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'migrate':
        message = sys.argv[2] if len(sys.argv) > 2 else "Auto migration"
        run_migration(message)
    elif command == 'upgrade':
        run_upgrade()
    elif command == 'init':
        run_init()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)