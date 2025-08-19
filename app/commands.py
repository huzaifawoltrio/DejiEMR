# /app/commands.py
import click
from flask.cli import with_appcontext
from app.extensions import db
from app.models.user_models import Role, Permission

@click.command('init-db')
@with_appcontext
def init_db_command():
    """Initialize database with HIPAA-compliant schema and defaults."""
    db.create_all()
    
    # --- Create default roles ---
    roles_data = [
        {'name': 'superadmin', 'description': 'Full system access'},
        {'name': 'admin', 'description': 'Administrative access'},
        {'name': 'doctor', 'description': 'Medical professional access'},
        {'name': 'nurse', 'description': 'Nursing staff access'},
        {'name': 'staff', 'description': 'General staff access'},
        {'name': 'patient', 'description': 'Patient portal access'}
    ]
    for role_data in roles_data:
        if not Role.query.filter_by(name=role_data['name']).first():
            db.session.add(Role(**role_data))
    db.session.commit() # Commit roles so they can be queried below

    # --- Create default permissions ---
    permissions_data = [
        # Patient Permissions
        {'name': 'read_patients', 'resource': 'patients', 'action': 'read'},
        {'name': 'write_patients', 'resource': 'patients', 'action': 'write'},
        # Doctor Permissions (New)
        {'name': 'read_doctors', 'resource': 'doctors', 'action': 'read'},
        {'name': 'write_doctors', 'resource': 'doctors', 'action': 'write'},
        # User & System Permissions
        {'name': 'admin_users', 'resource': 'users', 'action': 'admin'},
        {'name': 'view_audit', 'resource': 'audit', 'action': 'read'},
    ]
    for perm_data in permissions_data:
        if not Permission.query.filter_by(name=perm_data['name']).first():
            db.session.add(Permission(**perm_data))
    db.session.commit() # Commit permissions so they can be queried below

    # --- Assign permissions to roles ---
    
    # Superadmin gets all permissions
    superadmin = Role.query.filter_by(name='superadmin').first()
    all_permissions = Permission.query.all()
    superadmin.permissions = all_permissions
    
    # Admin gets most permissions, except full user administration
    admin = Role.query.filter_by(name='admin').first()
    admin_permissions = Permission.query.filter(
        Permission.name.in_([
            'read_patients', 'write_patients',
            'read_doctors', 'write_doctors',
            'view_audit'
        ])
    ).all()
    admin.permissions = admin_permissions

    # Doctor gets patient-related read/write permissions
    doctor = Role.query.filter_by(name='doctor').first()
    doctor_permissions = Permission.query.filter(
        Permission.name.in_(['read_patients', 'write_patients'])
    ).all()
    doctor.permissions = doctor_permissions

    db.session.commit()
    
    click.echo("Database initialized successfully with roles and permissions!")

def register_commands(app):
    app.cli.add_command(init_db_command)
