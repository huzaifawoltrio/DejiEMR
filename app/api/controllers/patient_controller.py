from flask import request, jsonify
from flask_jwt_extended import get_jwt_identity
from app.extensions import db
from app.models.patient_models import Patient
from app.utils.encryption_util import encryptor
from sqlalchemy.exc import IntegrityError

def _decrypt_patient_data(patient):
    """Helper function to decrypt a patient object for responses."""
    return {
        'id': patient.id,
        'doctor_id': patient.doctor_id,
        'full_name': encryptor.decrypt(patient.full_name),
        'date_of_birth': encryptor.decrypt(patient.date_of_birth),
        'gender': encryptor.decrypt(patient.gender),
        'email': encryptor.decrypt(patient.email),
        'phone_number': encryptor.decrypt(patient.phone_number),
        'address': encryptor.decrypt(patient.address),
        'presenting_problem': encryptor.decrypt(patient.presenting_problem),
        'billing_type': patient.billing_type,
        'age': patient.age,
        'created_at': patient.created_at.isoformat()
    }

def create_patient():
    """Creates a new patient record, linked to the current doctor."""
    data = request.get_json()
    doctor_id = get_jwt_identity()

    required_fields = ['full_name', 'date_of_birth', 'email', 'age']
    if any(field not in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    # Encrypt all sensitive fields before storing
    new_patient = Patient(
        doctor_id=doctor_id,
        full_name=encryptor.encrypt(data['full_name']),
        date_of_birth=encryptor.encrypt(data['date_of_birth']),
        email=encryptor.encrypt(data['email']),
        gender=encryptor.encrypt(data.get('gender')),
        phone_number=encryptor.encrypt(data.get('phone_number')),
        address=encryptor.encrypt(data.get('address')),
        presenting_problem=encryptor.encrypt(data.get('presenting_problem')),
        billing_type=data.get('billing_type'),
        age=data.get('age')
    )
    
    try:
        db.session.add(new_patient)
        db.session.commit()
        return jsonify({'message': 'Patient created successfully', 'patient': _decrypt_patient_data(new_patient)}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Patient with this email already exists.'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

def get_all_patients_for_doctor():
    """Retrieves all patients associated with the logged-in doctor."""
    doctor_id = get_jwt_identity()
    patients = Patient.query.filter_by(doctor_id=doctor_id).all()
    
    if not patients:
        return jsonify({'patients': []}), 200
        
    decrypted_patients = [_decrypt_patient_data(p) for p in patients]
    return jsonify({'patients': decrypted_patients}), 200

def get_patient_by_id(patient_id):
    """Retrieves a single patient by their ID."""
    doctor_id = get_jwt_identity()
    patient = Patient.query.filter_by(id=patient_id, doctor_id=doctor_id).first()
    
    if not patient:
        return jsonify({'error': 'Patient not found or you do not have permission to view this record.'}), 404
        
    return jsonify({'patient': _decrypt_patient_data(patient)}), 200

def update_patient(patient_id):
    """Updates an existing patient's record."""
    doctor_id = get_jwt_identity()
    patient = Patient.query.filter_by(id=patient_id, doctor_id=doctor_id).first()

    if not patient:
        return jsonify({'error': 'Patient not found or you do not have permission to edit this record.'}), 404

    data = request.get_json()
    
    # Update fields if they are provided in the request, encrypting them
    if 'full_name' in data: patient.full_name = encryptor.encrypt(data['full_name'])
    if 'date_of_birth' in data: patient.date_of_birth = encryptor.encrypt(data['date_of_birth'])
    if 'gender' in data: patient.gender = encryptor.encrypt(data['gender'])
    if 'email' in data: patient.email = encryptor.encrypt(data['email'])
    if 'phone_number' in data: patient.phone_number = encryptor.encrypt(data['phone_number'])
    if 'address' in data: patient.address = encryptor.encrypt(data['address'])
    if 'presenting_problem' in data: patient.presenting_problem = encryptor.encrypt(data['presenting_problem'])
    if 'billing_type' in data: patient.billing_type = data['billing_type']
    if 'age' in data: patient.age = data['age']

    try:
        db.session.commit()
        return jsonify({'message': 'Patient updated successfully', 'patient': _decrypt_patient_data(patient)}), 200
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Update failed, email may already be in use.'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

def delete_patient(patient_id):
    """Deletes a patient record."""
    doctor_id = get_jwt_identity()
    patient = Patient.query.filter_by(id=patient_id, doctor_id=doctor_id).first()

    if not patient:
        return jsonify({'error': 'Patient not found or you do not have permission to delete this record.'}), 404

    try:
        db.session.delete(patient)
        db.session.commit()
        return jsonify({'message': 'Patient deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500
