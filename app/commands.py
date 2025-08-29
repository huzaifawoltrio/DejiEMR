# huzaifawoltrio/dejiemr/DejiEMR-new-patient-profile/app/commands.py
import click
from flask.cli import with_appcontext
from .extensions import db
from .models.user_models import Role, Permission

@click.command(name='init_db')
@with_appcontext
def init_db_command():
    """Initializes the database by creating roles and permissions."""
    click.echo('Initializing the database...')
    
    # --- Create Roles ---
    roles = ['superadmin', 'doctor', 'patient', 'staff']
    for role_name in roles:
        if not Role.query.filter_by(name=role_name).first():
            db.session.add(Role(name=role_name, description=f'A {role_name} role'))
    db.session.commit()
    click.echo('Roles created successfully.')

    # --- Create Permissions ---
    permissions = [
        ('patients', 'read'), ('patients', 'write'),
        ('doctors', 'read'), ('doctors', 'write'),
        ('appointments', 'read'), ('appointments', 'write'),
        ('users', 'admin')
    ]
    for resource, action in permissions:
        permission_name = f"{resource}_{action}"
        if not Permission.query.filter_by(name=permission_name).first():
            db.session.add(Permission(name=permission_name, resource=resource, action=action))
    db.session.commit()
    click.echo('Permissions created successfully.')

    # --- Assign Permissions to Roles ---
    role_permissions_map = {
        'admin': ['users_admin', 'patients_read', 'patients_write', 'doctors_read', 'doctors_write', 'appointments_read', 'appointments_write'],
        'doctor': ['patients_read', 'patients_write', 'appointments_read', 'appointments_write'],
        'staff': ['patients_read', 'appointments_read'],
        'patient': ['appointments_read', 'appointments_write']
    }

    for role_name, perm_names in role_permissions_map.items():
        role = Role.query.filter_by(name=role_name).first()
        if role:
            for perm_name in perm_names:
                permission = Permission.query.filter_by(name=perm_name).first()
                if permission and permission not in role.permissions:
                    role.permissions.append(permission)
    
    db.session.commit()
    click.echo('Permissions assigned to roles successfully.')
    click.echo('Database initialization complete.')

# You can keep these individual commands if you still want to use them separately
@click.command(name='create_roles')
@with_appcontext
def create_roles():
    """Create user roles."""
    roles = ['admin', 'doctor', 'patient', 'staff']
    for role_name in roles:
        if not Role.query.filter_by(name=role_name).first():
            db.session.add(Role(name=role_name))
    db.session.commit()
    click.echo('Roles created successfully.')

@click.command(name='create_permissions')
@with_appcontext
def create_permissions():
    """Create permissions for resources."""
    permissions = [
        ('patients', 'read'), ('patients', 'write'),
        ('doctors', 'read'), ('doctors', 'write'),
        ('appointments', 'read'), ('appointments', 'write'),
        ('users', 'admin'),
    ]
    for resource, action in permissions:
        if not Permission.query.filter_by(resource=resource, action=action).first():
            db.session.add(Permission(name=f"{resource}_{action}", resource=resource, action=action))
    db.session.commit()
    click.echo('Permissions created successfully.')

@click.command(name='assign_permissions_to_role')
@click.argument('role_name')
@click.argument('permissions_str')
@with_appcontext
def assign_permissions_to_role(role_name, permissions_str):
    """Assign permissions to a role."""
    role = Role.query.filter_by(name=role_name).first()
    if not role:
        click.echo(f"Role '{role_name}' not found.")
        return

    permissions_list = [p.strip() for p in permissions_str.split(',')]
    for permission_name in permissions_list:
        resource, action = permission_name.split(':')
        permission = Permission.query.filter_by(resource=resource, action=action).first()
        if permission and permission not in role.permissions:
            role.permissions.append(permission)
            
    db.session.commit()
    click.echo(f"Permissions assigned to role '{role_name}' successfully.")
