# /create_db.py

from app import create_app
from app.extensions import db
from app.models.user_models import User, Role, Permission
from app.models.system_models import AuditLog, RevokedToken
from datetime import datetime

# Initialize the Flask application
# This is necessary to create a Flask app context for SQLAlchemy
app = create_app()

with app.app_context():
    print("--- Starting database setup ---")
    
    # Create all tables from the SQLAlchemy models.
    # This command creates tables for all models that inherit from db.Model.
    db.create_all()
    print("All database tables created successfully.")
    
    # --- Create initial roles and permissions ---
    # This prevents the 'Invalid role' error during user registration
    # by ensuring the roles exist before a user is assigned to one.
    
    # Check for existing roles to avoid duplicates
    existing_roles = Role.query.all()
    if not existing_roles:
        print("Creating initial roles...")
        superadmin_role = Role(name='superadmin', description='Super Administrator with full system access.')
        admin_role = Role(name='admin', description='System Administrator with elevated permissions.')
        patient_role = Role(name='patient', description='Patient user with basic access.')
        
        db.session.add_all([superadmin_role, admin_role, patient_role])
        db.session.commit()
        print("Initial roles created.")
    else:
        print("Roles already exist, skipping creation.")
    
    # Check for existing permissions to avoid duplicates
    existing_permissions = Permission.query.all()
    
    if not existing_permissions:
        print("Creating initial permissions...")
        users_admin_permission = Permission(name='users_admin', resource='users', action='admin', description='Full admin access to user management.')
        patients_read_permission = Permission(name='patients_read', resource='patients', action='read', description='Read access to patient records.')
        
        db.session.add_all([users_admin_permission, patients_read_permission])
        db.session.commit()
        print("Initial permissions created.")
    else:
        print("Permissions already exist, skipping creation.")

    # Link permissions to roles if they are not already linked
    # Retrieve the roles and permissions after creation or if they already exist
    superadmin_role = Role.query.filter_by(name='superadmin').first()
    admin_role = Role.query.filter_by(name='admin').first()
    patient_role = Role.query.filter_by(name='patient').first()
    
    users_admin_permission = Permission.query.filter_by(name='users_admin').first()
    patients_read_permission = Permission.query.filter_by(name='patients_read').first()

    if superadmin_role and users_admin_permission and patients_read_permission:
        if users_admin_permission not in superadmin_role.permissions:
            print("Assigning 'users_admin' permission to 'superadmin' role.")
            superadmin_role.permissions.append(users_admin_permission)
        
        if patients_read_permission not in superadmin_role.permissions:
            print("Assigning 'patients_read' permission to 'superadmin' role.")
            superadmin_role.permissions.append(patients_read_permission)
        
        db.session.commit()
        print("Permissions assigned to superadmin role.")
    else:
        print("Roles or permissions not found.")
    
    # Assign 'patients_read' to 'admin' and 'patient' roles
    if admin_role and patients_read_permission and patients_read_permission not in admin_role.permissions:
        print("Assigning 'patients_read' permission to 'admin' role.")
        admin_role.permissions.append(patients_read_permission)
        db.session.commit()
        print("Permission assigned to admin role.")

    if patient_role and patients_read_permission and patients_read_permission not in patient_role.permissions:
        print("Assigning 'patients_read' permission to 'patient' role.")
        patient_role.permissions.append(patients_read_permission)
        db.session.commit()
        print("Permission assigned to patient role.")

    print("--- Database setup complete ---")
