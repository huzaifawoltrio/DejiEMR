# /app/api/routes.py
from flask_jwt_extended import jwt_required
from . import api_bp
from app.extensions import limiter
from app.utils.decorators import audit_log, require_permission

# Import all controller functions
from .controllers import auth_controller, user_controller, patient_controller, doctor_controller

# --- Authentication Endpoints ---

@api_bp.route('/auth/register', methods=['POST'])
@limiter.limit("5 per hour")
@audit_log("USER_REGISTRATION", "users")
def register():
    return auth_controller.register_user()

@api_bp.route('/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
@audit_log("USER_LOGIN", "authentication")
def login():
    return auth_controller.login_user()

@api_bp.route('/auth/logout', methods=['POST'])
@jwt_required()
@audit_log("USER_LOGOUT", "authentication")
def logout():
    return auth_controller.logout_user()

@api_bp.route('/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    return auth_controller.refresh_token()

@api_bp.route('/auth/change-password', methods=['POST'])
@jwt_required()
@audit_log("PASSWORD_CHANGE", "authentication")
def change_password():
    return auth_controller.change_user_password()

# --- Doctor Endpoints ---

@api_bp.route('/doctors/register', methods=['POST'])
@limiter.limit("10 per hour")
@audit_log("DOCTOR_REGISTRATION", "doctors")
# @require_permission('doctors', 'create') # Optional: Uncomment when permissions are set up
def register_doctor():
    return doctor_controller.register_doctor()

@api_bp.route('/doctors', methods=['GET'])
@jwt_required()
@audit_log("VIEW_ALL_DOCTORS", "doctors")
# @require_permission('doctors', 'read') # Optional: Uncomment when permissions are set up
def get_doctors():
    return doctor_controller.get_all_doctors()

# --- Protected Example Endpoints ---

@api_bp.route('/patients', methods=['GET'])
@jwt_required() # Ensuring user is logged in
@require_permission('patients', 'read')
@audit_log("VIEW_PATIENTS", "patients")
def get_patients():
    return patient_controller.get_all_patients()

@api_bp.route('/test-auth', methods=['GET'])
@jwt_required()
def test_auth():
    return user_controller.test_user_auth()

@api_bp.route('/admin/users', methods=['GET'])
@jwt_required() # Ensuring user is logged in
@require_permission('users', 'admin')
@audit_log("VIEW_ALL_USERS", "users")
def get_all_users():
    return user_controller.get_all_users_list()
