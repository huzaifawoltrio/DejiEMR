from flask_jwt_extended import jwt_required
from . import api_bp
from app.extensions import limiter
from app.utils.decorators import audit_log, require_permission
from .controllers import auth_controller, user_controller, patient_controller, doctor_controller

# ... (Authentication and Doctor endpoints remain the same) ...
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
@jwt_required()
@limiter.limit("10 per hour")
@audit_log("DOCTOR_REGISTRATION", "doctors")
@require_permission('doctors', 'write')
def register_doctor():
    return doctor_controller.register_doctor()

@api_bp.route('/doctors', methods=['GET'])
@jwt_required()
@audit_log("VIEW_ALL_DOCTORS", "doctors")
@require_permission('doctors', 'read')
def get_doctors():
    return doctor_controller.get_all_doctors()


# --- NEW: Patient CRUD Endpoints ---

@api_bp.route('/patients', methods=['POST'])
@jwt_required()
@require_permission('patients', 'write')
@audit_log("CREATE_PATIENT", "patients")
def create_patient_route():
    return patient_controller.create_patient()

@api_bp.route('/patients', methods=['GET'])
@jwt_required()
@require_permission('patients', 'read')
@audit_log("VIEW_ALL_PATIENTS", "patients")
def get_patients_route():
    return patient_controller.get_all_patients_for_doctor()

@api_bp.route('/patients/<int:patient_id>', methods=['GET'])
@jwt_required()
@require_permission('patients', 'read')
@audit_log("VIEW_PATIENT_DETAIL", "patients")
def get_patient_route(patient_id):
    return patient_controller.get_patient_by_id(patient_id)

@api_bp.route('/patients/<int:patient_id>', methods=['PUT'])
@jwt_required()
@require_permission('patients', 'write')
@audit_log("UPDATE_PATIENT", "patients")
def update_patient_route(patient_id):
    return patient_controller.update_patient(patient_id)

@api_bp.route('/patients/<int:patient_id>', methods=['DELETE'])
@jwt_required()
@require_permission('patients', 'write')
@audit_log("DELETE_PATIENT", "patients")
def delete_patient_route(patient_id):
    return patient_controller.delete_patient(patient_id)


# --- Admin & Test Endpoints ---
@api_bp.route('/test-auth', methods=['GET'])
@jwt_required()
def test_auth():
    return user_controller.test_user_auth()

@api_bp.route('/admin/users', methods=['GET'])
@jwt_required()
@require_permission('users', 'admin')
@audit_log("VIEW_ALL_USERS", "users")
def get_all_users():
    return user_controller.get_all_users_list()
