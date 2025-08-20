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
    db.session.commit()

    # --- Create default permissions ---
    permissions_data = [
        {'name': 'read_patients', 'resource': 'patients', 'action': 'read'},
        {'name': 'write_patients', 'resource': 'patients', 'action': 'write'},
        {'name': 'read_doctors', 'resource': 'doctors', 'action': 'read'},
        {'name': 'write_doctors', 'resource': 'doctors', 'action': 'write'},
        {'name': 'admin_users', 'resource': 'users', 'action': 'admin'},
        {'name': 'view_audit', 'resource': 'audit', 'action': 'read'},
    ]
    for perm_data in permissions_data:
        if not Permission.query.filter_by(name=perm_data['name']).first():
            db.session.add(Permission(**perm_data))
    db.session.commit()

    # --- Assign permissions to roles ---
    superadmin = Role.query.filter_by(name='superadmin').first()
    admin = Role.query.filter_by(name='admin').first()
    doctor = Role.query.filter_by(name='doctor').first()

    write_doctors_perm = Permission.query.filter_by(name='write_doctors').first()
    read_doctors_perm = Permission.query.filter_by(name='read_doctors').first()
    write_patients_perm = Permission.query.filter_by(name='write_patients').first()
    read_patients_perm = Permission.query.filter_by(name='read_patients').first()
    view_audit_perm = Permission.query.filter_by(name='view_audit').first()

    # Superadmin gets all permissions
    superadmin.permissions = Permission.query.all()
    
    # Admin gets permissions to view data and audits, but not create doctors
    admin.permissions = [
        read_patients_perm, 
        write_patients_perm,
        read_doctors_perm,
        view_audit_perm
    ]

    # Doctor gets patient-related read/write permissions
    doctor.permissions = [read_patients_perm, write_patients_perm]

    db.session.commit()
    
    click.echo("Database initialized successfully with roles and permissions!")

def register_commands(app):
    app.cli.add_command(init_db_command)