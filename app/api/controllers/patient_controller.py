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
    """Generates a secure, random password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in password) and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password) and any(c in string.punctuation for c in password)):
            return password

def _decrypt_patient_data(patient_user):
    """Helper to decrypt a patient's user and profile data for responses."""
    if not patient_user or not patient_user.patient_profile:
        return None
    profile = patient_user.patient_profile
    return {
        'user_id': patient_user.id,
        'username': encryptor.decrypt(patient_user.username),
        'email': encryptor.decrypt(patient_user.email),
        'full_name': encryptor.decrypt(profile.full_name),
        'date_of_birth': encryptor.decrypt(profile.date_of_birth),
        'gender': encryptor.decrypt(profile.gender),
        'phone_number': encryptor.decrypt(profile.phone_number),
        'address': encryptor.decrypt(profile.address),
        'presenting_problem': encryptor.decrypt(profile.presenting_problem),
        'billing_type': profile.billing_type,
        'age': profile.age,
        'is_active': patient_user.is_active
    }

def register_patient():
    """Creates a new patient as a user and links them to the current doctor."""
    doctor_id = get_jwt_identity()
    doctor = User.query.get(doctor_id)
    data = request.get_json()

    required = ['username', 'email', 'full_name', 'date_of_birth', 'age']
    if any(field not in data for field in required):
        return jsonify({'error': 'Missing required fields'}), 400

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

    patient_profile = PatientProfile(
        user=patient_user,
        full_name=encryptor.encrypt(data['full_name']),
        date_of_birth=encryptor.encrypt(data['date_of_birth']),
        gender=encryptor.encrypt(data.get('gender')),
        phone_number=encryptor.encrypt(data.get('phone_number')),
        address=encryptor.encrypt(data.get('address')),
        presenting_problem=encryptor.encrypt(data.get('presenting_problem')),
        billing_type=data.get('billing_type'),
        age=data.get('age')
    )
    
    # Associate the new patient with the doctor
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

def update_patient(patient_id):
    """Updates an assigned patient's user and profile data."""
    doctor_id = get_jwt_identity()
    doctor = User.query.get(doctor_id)
    patient = doctor.assigned_patients.filter_by(id=patient_id).first()

    if not patient:
        return jsonify({'error': 'Patient not found or not assigned to you.'}), 404

    data = request.get_json()
    profile = patient.patient_profile
    
    # Update profile fields
    if 'full_name' in data: profile.full_name = encryptor.encrypt(data['full_name'])
    # ... update other profile fields as needed ...

    # Update user fields (like email)
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
