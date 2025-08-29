import secrets
import string
from flask import request, jsonify
from flask_jwt_extended import get_jwt_identity
from app.extensions import db
from app.models.user_models import User, Role
from app.models.patient_profile_models import PatientProfile
from app.utils.encryption_util import encryptor
from app.utils.email_util import send_password_email
from sqlalchemy.exc import IntegrityError

def _generate_random_password(length=12):
    """Generates a secure, random 12-character password with required complexity."""
    all_chars = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(all_chars) for _ in range(length))
        if (any(c.islower() for c in password) and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password) and any(c in string.punctuation for c in password)):
            return password

def _decrypt_patient_data(patient_user):
    """Helper to decrypt a patient's user and profile data for responses."""
    if not patient_user or not patient_user.patient_profile:
        return None
    profile = patient_user.patient_profile
    
    # Helper to safely decrypt a field
    def safe_decrypt(field):
        return encryptor.decrypt(field) if field else None

    return {
        'user_id': patient_user.id,
        'username': safe_decrypt(patient_user.username),
        'email': safe_decrypt(patient_user.email),
        'first_name': safe_decrypt(profile.first_name),
        'last_name': safe_decrypt(profile.last_name),
        'date_of_birth': safe_decrypt(profile.date_of_birth),
        'gender': safe_decrypt(profile.gender),
        'phone_number': safe_decrypt(profile.phone_number),
        'address': safe_decrypt(profile.address),
        'city': safe_decrypt(profile.city),
        'state': safe_decrypt(profile.state),
        'zip_code': safe_decrypt(profile.zip_code),
        'emergency_contact_name': safe_decrypt(profile.emergency_contact_name),
        'emergency_contact_phone': safe_decrypt(profile.emergency_contact_phone),
        'insurance_provider': safe_decrypt(profile.insurance_provider),
        'policy_number': safe_decrypt(profile.policy_number),
        'group_number': safe_decrypt(profile.group_number),
        'policy_holder_name': safe_decrypt(profile.policy_holder_name),
        'policy_holder_date_of_birth': safe_decrypt(profile.policy_holder_date_of_birth),
        'relationship_to_patient': safe_decrypt(profile.relationship_to_patient),
        'primary_care_physician': safe_decrypt(profile.primary_care_physician),
        'allergies': safe_decrypt(profile.allergies),
        'current_medications': safe_decrypt(profile.current_medications),
        'previous_surgeries': safe_decrypt(profile.previous_surgeries),
        'family_medical_history': safe_decrypt(profile.family_medical_history),
        'smoking_status': safe_decrypt(profile.smoking_status),
        'alcohol_consumption': safe_decrypt(profile.alcohol_consumption),
        'exercise_frequency': safe_decrypt(profile.exercise_frequency),
        'chief_complaint': safe_decrypt(profile.chief_complaint),
        'symptoms_duration': safe_decrypt(profile.symptoms_duration),
        'previous_treatment_for_condition': safe_decrypt(profile.previous_treatment_for_condition),
        'additional_notes': safe_decrypt(profile.additional_notes),
        'current_pain_level': profile.current_pain_level,
        'is_active': patient_user.is_active
    }

def register_patient():
    """Creates a new patient with a comprehensive profile and links to the current doctor."""
    doctor_id = get_jwt_identity()
    doctor = User.query.get(doctor_id)
    data = request.get_json()

    required = ['username', 'email', 'first_name', 'last_name', 'date_of_birth']
    if any(field not in data for field in required):
        return jsonify({'error': 'Missing required fields: username, email, first_name, last_name, date_of_birth'}), 400

    username, email = data['username'], data['email']
    if User.query.filter_by(username_hash=User.create_hash(username)).first() or \
       User.query.filter_by(email_hash=User.create_hash(email)).first():
        return jsonify({'error': 'Username or email already exists'}), 409

    patient_role = Role.query.filter_by(name='patient').first()
    if not patient_role:
        return jsonify({'error': "The 'patient' role has not been configured."}), 500

    temp_password = _generate_random_password()
    
    patient_user = User(
        username=encryptor.encrypt(username),
        email=encryptor.encrypt(email),
        username_hash=User.create_hash(username),
        email_hash=User.create_hash(email),
        role_id=patient_role.id,
        must_change_password=True
    )
    patient_user.set_password(temp_password)
    
    # Helper to safely encrypt a field from data if it exists
    def safe_encrypt(field_name):
        return encryptor.encrypt(data[field_name]) if data.get(field_name) else None

    patient_profile = PatientProfile( 
        user=patient_user,
        first_name=safe_encrypt('first_name'),
        last_name=safe_encrypt('last_name'),
        date_of_birth=safe_encrypt('date_of_birth'),
        gender=safe_encrypt('gender'),
        phone_number=safe_encrypt('phone_number'),
        address=safe_encrypt('address'),
        city=safe_encrypt('city'),
        state=safe_encrypt('state'),
        zip_code=safe_encrypt('zip_code'),
        emergency_contact_name=safe_encrypt('emergency_contact_name'),
        emergency_contact_phone=safe_encrypt('emergency_contact_phone'),
        insurance_provider=safe_encrypt('insurance_provider'),
        policy_number=safe_encrypt('policy_number'),
        group_number=safe_encrypt('group_number'),
        policy_holder_name=safe_encrypt('policy_holder_name'),
        policy_holder_date_of_birth=safe_encrypt('policy_holder_date_of_birth'),
        relationship_to_patient=safe_encrypt('relationship_to_patient'),
        primary_care_physician=safe_encrypt('primary_care_physician'),
        allergies=safe_encrypt('allergies'),
        current_medications=safe_encrypt('current_medications'),
        previous_surgeries=safe_encrypt('previous_surgeries'),
        family_medical_history=safe_encrypt('family_medical_history'),
        smoking_status=safe_encrypt('smoking_status'),
        alcohol_consumption=safe_encrypt('alcohol_consumption'),
        exercise_frequency=safe_encrypt('exercise_frequency'),
        chief_complaint=safe_encrypt('chief_complaint'),
        symptoms_duration=safe_encrypt('symptoms_duration'),
        previous_treatment_for_condition=safe_encrypt('previous_treatment_for_condition'),
        additional_notes=safe_encrypt('additional_notes'),
        current_pain_level=data.get('current_pain_level')
    )
    
    doctor.assigned_patients.append(patient_user)

    try:
        db.session.add(patient_user)
        db.session.commit()
        send_password_email(email, username, temp_password)
        return jsonify({
            'message': 'Patient registered successfully. Credentials sent to their email.',
            'patient': _decrypt_patient_data(patient_user)
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

def update_patient(patient_id):
    """Updates an assigned patient's comprehensive profile data."""
    doctor_id = get_jwt_identity()
    doctor = User.query.get(doctor_id)
    patient = doctor.assigned_patients.filter_by(id=patient_id).first()

    if not patient:
        return jsonify({'error': 'Patient not found or not assigned to you.'}), 404

    data = request.get_json()
    profile = patient.patient_profile
    
    # List of all profile fields to update
    profile_fields = [
        'first_name', 'last_name', 'date_of_birth', 'gender', 'phone_number', 
        'address', 'city', 'state', 'zip_code', 'emergency_contact_name', 
        'emergency_contact_phone', 'insurance_provider', 'policy_number', 
        'group_number', 'policy_holder_name', 'policy_holder_date_of_birth', 
        'relationship_to_patient', 'primary_care_physician', 'allergies', 
        'current_medications', 'previous_surgeries', 'family_medical_history', 
        'smoking_status', 'alcohol_consumption', 'exercise_frequency', 
        'chief_complaint', 'symptoms_duration', 'previous_treatment_for_condition', 
        'additional_notes'
    ]

    for field in profile_fields:
        if field in data:
            setattr(profile, field, encryptor.encrypt(data[field]))
    
    if 'current_pain_level' in data:
        profile.current_pain_level = data['current_pain_level']

    if 'email' in data and encryptor.decrypt(patient.email) != data['email']:
        patient.email = encryptor.encrypt(data['email'])
        patient.email_hash = User.create_hash(data['email'])

    try:
        db.session.commit()
        return jsonify({'message': 'Patient updated successfully', 'patient': _decrypt_patient_data(patient)}), 200
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Update failed, email may already be in use.'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

def get_all_patients_for_doctor():
    """Retrieves all patients assigned to the logged-in doctor."""
    doctor_id = get_jwt_identity()
    doctor = User.query.get(doctor_id)
    patients = doctor.assigned_patients.all()
    
    decrypted_patients = [_decrypt_patient_data(p) for p in patients]
    return jsonify({'patients': decrypted_patients}), 200

def get_patient_by_id(patient_id):
    """Retrieves a single assigned patient by their user ID."""
    doctor_id = get_jwt_identity()
    doctor = User.query.get(doctor_id)
    
    patient = doctor.assigned_patients.filter_by(id=patient_id).first()
    
    if not patient:
        return jsonify({'error': 'Patient not found or not assigned to you.'}), 404
        
    return jsonify({'patient': _decrypt_patient_data(patient)}), 200

def get_patient_by_username(username):
    """Retrieves a single assigned patient by their username."""
    doctor_id = get_jwt_identity()
    doctor = User.query.get(doctor_id)
    
    # Find the user by their username hash for security
    username_hash = User.create_hash(username)
    patient = User.query.filter_by(username_hash=username_hash).first()

    if not patient:
        return jsonify({'error': 'Patient with that username not found.'}), 404

    # Check if the found user is actually assigned to this doctor
    is_assigned = doctor.assigned_patients.filter_by(id=patient.id).first()
    
    if not is_assigned:
        return jsonify({'error': 'Patient not found or not assigned to you.'}), 404
        
    return jsonify({'patient': _decrypt_patient_data(patient)}), 200

def disassociate_patient(patient_id):
    """Removes the link between a doctor and a patient, without deleting the patient."""
    doctor_id = get_jwt_identity()
    doctor = User.query.get(doctor_id)
    patient = doctor.assigned_patients.filter_by(id=patient_id).first()

    if not patient:
        return jsonify({'error': 'Patient not found or not assigned to you.'}), 404

    try:
        doctor.assigned_patients.remove(patient)
        db.session.commit()
        return jsonify({'message': 'Patient has been disassociated from your record.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500
