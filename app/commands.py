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
    # ... (no changes here) ...
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
        # NEW: Appointment permissions
        {'name': 'read_appointments', 'resource': 'appointments', 'action': 'read'},
        {'name': 'write_appointments', 'resource': 'appointments', 'action': 'write'},
        # User & System Permissions
        {'name': 'admin_users', 'resource': 'users', 'action': 'admin'},
        {'name': 'view_audit', 'resource': 'audit', 'action': 'read'},
        # NEW: Chat permissions
        {'name': 'read_chat', 'resource': 'chat', 'action': 'read'},
        {'name': 'write_chat', 'resource': 'chat', 'action': 'write'},
    ]
    for perm_data in permissions_data:
        if not Permission.query.filter_by(name=perm_data['name']).first():
            db.session.add(Permission(**perm_data))
    db.session.commit()

    # --- Assign permissions to roles ---
    superadmin = Role.query.filter_by(name='superadmin').first()
    admin = Role.query.filter_by(name='admin').first()
    doctor = Role.query.filter_by(name='doctor').first()
    patient = Role.query.filter_by(name='patient').first()

    # Superadmin gets all permissions
    superadmin.permissions = Permission.query.all()
    
    # Admin gets most view/audit permissions
    admin.permissions = [p for p in Permission.query.all() if p.action == 'read']

    # Doctor gets permissions for patients and appointments
    doctor.permissions = Permission.query.filter(
        Permission.resource.in_(['patients', 'appointments'])
    ).all()

    # Patient gets permissions for their own appointments
    patient.permissions = Permission.query.filter(
        Permission.resource == 'appointments'
    ).all()

    db.session.commit()
    
    click.echo("Database initialized successfully with roles and permissions!")

@click.command('init-templates')
@with_appcontext
def init_templates_command():
    """Initialize database with default clinical note templates."""
    from app.models.clinical_notes_models import NoteTemplate, DEFAULT_TEMPLATES
    
    for template_data in DEFAULT_TEMPLATES:
        # Check if template already exists
        existing = NoteTemplate.query.filter_by(name=template_data['name']).first()
        if not existing:
            template = NoteTemplate(
                name=template_data['name'],
                description=template_data['description'],
                note_type=template_data['note_type'],
                schema=template_data['schema'],
                is_active=True,
                version='1.0'
            )
            db.session.add(template)
            click.echo(f"Added template: {template_data['name']}")
        else:
            click.echo(f"Template already exists: {template_data['name']}")
    
    db.session.commit()
    click.echo("Note templates initialized successfully!")

def register_commands(app):
    app.cli.add_command(init_db_command)
    app.cli.add_command(init_templates_command)  # Add this line    