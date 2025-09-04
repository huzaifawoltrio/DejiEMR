# huzaifawoltrio/dejiemr/DejiEMR-new-patient-profile/app/api/routes.py

from flask_jwt_extended import jwt_required
from . import api_bp
from app.extensions import limiter
from app.utils.decorators import audit_log, require_permission
from .controllers import auth_controller, user_controller, patient_controller, doctor_controller, appointment_controller
from app.api.controllers import google_calendar_controller
from .controllers import clinical_notes_controller



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


# --- User Profile Endpoint ---
@api_bp.route('/users/me', methods=['GET'])
@jwt_required()
@audit_log("VIEW_OWN_PROFILE", "users")
def get_current_user_route():
    return user_controller.get_current_user_details()


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

@api_bp.route('/doctors/profile', methods=['GET'])
@jwt_required()
@audit_log("VIEW_DOCTOR_PROFILE", "doctors")
def get_doctor_profile():
    return doctor_controller.get_doctor_profile()


# --- Patient Management Endpoints ---
@api_bp.route('/patients/register', methods=['POST'])
@jwt_required()
@require_permission('patients', 'write')
@audit_log("PATIENT_REGISTRATION", "patients")
def register_patient_route():
    return patient_controller.register_patient()

@api_bp.route('/patients', methods=['GET'])
@jwt_required()
@require_permission('patients', 'read')
@audit_log("VIEW_ALL_PATIENTS", "patients")
def get_patients_route():
    return patient_controller.get_all_patients_for_doctor()

@api_bp.route('/patients/detailed', methods=['GET'])
@jwt_required()
@require_permission('patients', 'read')
@audit_log("VIEW_ALL_PATIENTS_DETAILED", "patients")
def get_patients_detailed_route():
    return patient_controller.get_all_patients_for_doctor_detailed()

@api_bp.route('/patients/my-doctors', methods=['GET'])
@jwt_required()
@audit_log("VIEW_ASSIGNED_DOCTORS", "patients")
def get_my_doctors_route():
    return doctor_controller.get_my_doctors()

@api_bp.route('/patients/search/<string:username>', methods=['GET'])
@jwt_required()
@require_permission('patients', 'read')
@audit_log("SEARCH_PATIENT_BY_USERNAME", "patients")
def get_patient_by_username_route(username):
    return patient_controller.get_patient_by_username(username)

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
@audit_log("DISASSOCIATE_PATIENT", "patients")
def disassociate_patient_route(patient_id):
    return patient_controller.disassociate_patient(patient_id)


# --- Appointment CRUD Endpoints ---
@api_bp.route('/appointments', methods=['POST'])
@jwt_required()
@require_permission('appointments', 'write')
@audit_log("CREATE_APPOINTMENT", "appointments")
def create_appointment_route():
    return appointment_controller.create_appointment()

@api_bp.route('/appointments', methods=['GET'])
@jwt_required()
@require_permission('appointments', 'read')
@audit_log("VIEW_ALL_APPOINTMENTS", "appointments")
def get_appointments_route():
    return appointment_controller.get_appointments()

@api_bp.route('/appointments/<int:appointment_id>', methods=['GET'])
@jwt_required()
@require_permission('appointments', 'read')
@audit_log("VIEW_APPOINTMENT_DETAIL", "appointments")
def get_appointment_route(appointment_id):
    return appointment_controller.get_appointment_by_id(appointment_id)

@api_bp.route('/appointments/<int:appointment_id>', methods=['PUT'])
@jwt_required()
@require_permission('appointments', 'write')
@audit_log("UPDATE_APPOINTMENT", "appointments")
def update_appointment_route(appointment_id):
    return appointment_controller.update_appointment(appointment_id)

@api_bp.route('/appointments/<int:appointment_id>', methods=['DELETE'])
@jwt_required()
@require_permission('appointments', 'write')
@audit_log("DELETE_APPOINTMENT", "appointments")
def delete_appointment_route(appointment_id):
    return appointment_controller.delete_appointment(appointment_id)


# --- Profile Picture Endpoints ---
@api_bp.route('/profile/picture', methods=['POST'])
@jwt_required()
@limiter.limit("3 per minute")
@audit_log("UPLOAD_PROFILE_PICTURE", "profile")
def upload_profile_picture_route():
    from .controllers import profile_controller
    return profile_controller.upload_profile_picture()

@api_bp.route('/profile/picture', methods=['GET'])
@jwt_required()
@audit_log("VIEW_PROFILE_PICTURE", "profile")
def get_profile_picture_route():
    from .controllers import profile_controller
    return profile_controller.get_profile_picture()

@api_bp.route('/profile/picture', methods=['DELETE'])
@jwt_required()
@audit_log("DELETE_PROFILE_PICTURE", "profile")
def delete_profile_picture_route():
    from .controllers import profile_controller
    return profile_controller.delete_profile_picture()

@api_bp.route('/users/<int:user_id>/picture', methods=['GET'])
@jwt_required()
@audit_log("VIEW_USER_PROFILE_PICTURE", "profile")
def get_user_profile_picture_route(user_id):
    from .controllers import profile_controller
    return profile_controller.get_user_profile_picture(user_id)


# --- Chat Endpoints ---
@api_bp.route('/chat/history', methods=['GET'])
@jwt_required()
@audit_log("VIEW_CHAT_HISTORY", "chat")
def get_chat_history_route():
    from .controllers import chat_controller
    return chat_controller.get_chat_history()

@api_bp.route('/chat/conversations', methods=['GET'])
@jwt_required()
@audit_log("VIEW_CONVERSATIONS", "chat")
def get_conversations_route():
    from .controllers import chat_controller
    return chat_controller.get_conversations()

@api_bp.route('/chat/users', methods=['GET'])
@jwt_required()
@audit_log("VIEW_CHATEABLE_USERS", "chat")
def get_chateable_users_route():
    from .controllers import chat_controller
    return chat_controller.get_chateable_users()

@api_bp.route('/chat/messages/<int:message_id>', methods=['DELETE'])
@jwt_required()
@audit_log("DELETE_CHAT_MESSAGE", "chat")
def delete_message_route(message_id):
    from .controllers import chat_controller
    return chat_controller.delete_message(message_id)

@api_bp.route('/chat/mark-read', methods=['POST'])
@jwt_required()
@audit_log("MARK_MESSAGES_READ", "chat")
def mark_messages_read_route():
    from .controllers import chat_controller
    return chat_controller.mark_messages_read()


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

# --- Google Calendar/Meet Integration Endpoints ---
# REMOVED @jwt_required() from OAuth authorization endpoint - this is PUBLIC
@api_bp.route('/google/authorize', methods=['GET'])
@audit_log("GOOGLE_AUTH_INITIATE", "google")
def authorize():
    return google_calendar_controller.authorize()

# OAuth callback endpoint should also be public - REMOVED @jwt_required()
@api_bp.route('/google/oauth2callback', methods=['GET'])
def oauth2callback():
    return google_calendar_controller.oauth2callback()

@api_bp.route('/google/status', methods=['GET'])
@jwt_required()
def check_google_status():
    return google_calendar_controller.check_google_connection()

@api_bp.route('/google/disconnect', methods=['POST'])
@jwt_required()
@audit_log("GOOGLE_DISCONNECT", "google")
def disconnect_google():
    return google_calendar_controller.disconnect_google()

# --- Enhanced Meeting Endpoints with Patient Linking ---
@api_bp.route('/meetings', methods=['POST'])
@jwt_required()
@audit_log("CREATE_GOOGLE_MEET", "meetings")
def create_meeting():
    return google_calendar_controller.create_google_meet_event()

@api_bp.route('/meetings', methods=['GET'])
@jwt_required()
@audit_log("VIEW_MEETINGS", "meetings")
def get_meetings():
    return google_calendar_controller.get_meetings()

@api_bp.route('/meetings/patient/<int:patient_id>', methods=['GET'])
@jwt_required()
@audit_log("VIEW_PATIENT_MEETINGS", "meetings")
def get_patient_meetings_route(patient_id):
    return google_calendar_controller.get_patient_meetings(patient_id)

@api_bp.route('/meetings/<string:event_id>/reschedule', methods=['PUT'])
@jwt_required()
@audit_log("RESCHEDULE_GOOGLE_MEET", "meetings")
def reschedule_meeting(event_id):
    data = request.get_json()
    return google_calendar_controller.reschedule_event(
        event_id, 
        data.get('start_time'), 
        data.get('end_time')
    )

@api_bp.route('/meetings/<string:event_id>/cancel', methods=['DELETE'])
@jwt_required()
@audit_log("CANCEL_GOOGLE_MEET", "meetings")
def cancel_meeting(event_id):
    return google_calendar_controller.cancel_event(event_id)




# --- Clinical Notes Endpoints -----------------------------------------

# --- Clinical Notes Template Endpoints ---
@api_bp.route('/clinical-notes/templates', methods=['GET'])
@jwt_required()
@audit_log("VIEW_NOTE_TEMPLATES", "clinical_notes")
def get_note_templates():
    return clinical_notes_controller.get_note_templates()

@api_bp.route('/clinical-notes/templates/<int:template_id>', methods=['GET'])
@jwt_required()
@audit_log("VIEW_NOTE_TEMPLATE", "clinical_notes")
def get_note_template(template_id):
    return clinical_notes_controller.get_note_template(template_id)

# --- Clinical Notes CRUD Endpoints ---
@api_bp.route('/clinical-notes', methods=['POST'])
@jwt_required()
@require_permission('clinical_notes', 'write')
@audit_log("CREATE_CLINICAL_NOTE", "clinical_notes")
def create_clinical_note():
    return clinical_notes_controller.create_clinical_note()

@api_bp.route('/clinical-notes/<int:note_id>', methods=['GET'])
@jwt_required()
@require_permission('clinical_notes', 'read')
@audit_log("VIEW_CLINICAL_NOTE", "clinical_notes")
def get_clinical_note(note_id):
    return clinical_notes_controller.get_clinical_note(note_id)

@api_bp.route('/clinical-notes/<int:note_id>', methods=['PUT'])
@jwt_required()
@require_permission('clinical_notes', 'write')
@audit_log("UPDATE_CLINICAL_NOTE", "clinical_notes")
def update_clinical_note(note_id):
    return clinical_notes_controller.update_clinical_note(note_id)

@api_bp.route('/clinical-notes/<int:note_id>', methods=['DELETE'])
@jwt_required()
@require_permission('clinical_notes', 'write')
@audit_log("DELETE_CLINICAL_NOTE", "clinical_notes")
def delete_clinical_note(note_id):
    return clinical_notes_controller.delete_clinical_note(note_id)

# --- Clinical Notes Actions ---
@api_bp.route('/clinical-notes/<int:note_id>/sign', methods=['POST'])
@jwt_required()
@require_permission('clinical_notes', 'write')
@audit_log("SIGN_CLINICAL_NOTE", "clinical_notes")
def sign_clinical_note(note_id):
    return clinical_notes_controller.sign_clinical_note(note_id)

@api_bp.route('/clinical-notes/<int:note_id>/amend', methods=['POST'])
@jwt_required()
@require_permission('clinical_notes', 'write')
@audit_log("AMEND_CLINICAL_NOTE", "clinical_notes")
def amend_clinical_note(note_id):
    return clinical_notes_controller.amend_clinical_note(note_id)

@api_bp.route('/clinical-notes/<int:note_id>/amendments', methods=['GET'])
@jwt_required()
@require_permission('clinical_notes', 'read')
@audit_log("VIEW_NOTE_AMENDMENTS", "clinical_notes")
def get_note_amendments(note_id):
    return clinical_notes_controller.get_note_amendments(note_id)

# --- Patient-specific Notes ---
@api_bp.route('/patients/<int:patient_id>/clinical-notes', methods=['GET'])
@jwt_required()
@require_permission('clinical_notes', 'read')
@audit_log("VIEW_PATIENT_NOTES", "clinical_notes")
def get_patient_notes(patient_id):
    return clinical_notes_controller.get_patient_notes(patient_id)

# --- Appointment-specific Notes ---
@api_bp.route('/appointments/<int:appointment_id>/clinical-notes', methods=['GET'])
@jwt_required()
@require_permission('clinical_notes', 'read')
@audit_log("VIEW_APPOINTMENT_NOTES", "clinical_notes")
def get_appointment_notes(appointment_id):
    return clinical_notes_controller.get_appointment_notes(appointment_id)

# --- Search Notes ---
@api_bp.route('/clinical-notes/search', methods=['GET'])
@jwt_required()
@require_permission('clinical_notes', 'read')
@audit_log("SEARCH_CLINICAL_NOTES", "clinical_notes")
def search_notes():
    return clinical_notes_controller.search_notes()