from flask import request, jsonify
from flask_jwt_extended import get_jwt_identity
from app.extensions import db
from app.models.user_models import User
from app.models.appointment_models import Appointment
from datetime import datetime

def _serialize_appointment(appt):
    """Helper function to format appointment data for API responses."""
    return {
        "id": appt.id,
        "doctor_id": appt.doctor_id,
        "patient_id": appt.patient_id,
        "appointment_datetime": appt.appointment_datetime.isoformat(),
        "duration": appt.duration,
        "location": appt.location,
        "services": appt.services,
        "appointment_fee": appt.appointment_fee,
        "billing_type": appt.billing_type,
        "repeat": appt.repeat,
        "status": appt.status
    }

def create_appointment():
    """Creates a new appointment, handling different user roles."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.get_json()

    required = ['appointment_datetime']
    if any(field not in data for field in required):
        return jsonify({"error": "Missing required appointment_datetime"}), 400

    doctor_id, patient_id = None, None
    user_role = user.role.name

    # Case 1: The creator is a Doctor
    if user_role == 'doctor':
        doctor_id = user.id
        patient_id = data.get('patient_id')
        if not patient_id:
            return jsonify({"error": "As a doctor, you must provide a patient_id"}), 400
        
        patient = user.assigned_patients.filter_by(id=patient_id).first()
        if not patient:
            return jsonify({"error": "Patient not found or is not assigned to you"}), 404

    # Case 2: The creator is a Patient
    elif user_role == 'patient':
        patient_id = user.id
        doctor_id = data.get('doctor_id')
        if not doctor_id:
            return jsonify({"error": "As a patient, you must provide a doctor_id"}), 400
            
        doctor = user.assigned_doctors.filter_by(id=doctor_id).first()
        if not doctor:
            return jsonify({"error": "Doctor not found or you are not assigned to them"}), 404
            
    # Case 3: The creator is an Admin/Superadmin
    elif user_role in ['superadmin', 'admin']:
         doctor_id = data.get('doctor_id')
         patient_id = data.get('patient_id')
         if not doctor_id or not patient_id:
             return jsonify({"error": "As an admin, you must provide both a doctor_id and a patient_id"}), 400
        
         # Verify that the specified users exist
         if not User.query.get(doctor_id) or not User.query.get(patient_id):
             return jsonify({"error": "The specified doctor or patient ID is invalid"}), 404

    # Case 4: Any other role is forbidden
    else:
        return jsonify({"error": "Your role does not permit creating appointments"}), 403

    # --- Create the appointment ---
    new_appointment = Appointment(
        doctor_id=doctor_id,
        patient_id=patient_id,
        appointment_datetime=datetime.fromisoformat(data['appointment_datetime']),
        duration=data.get('duration'),
        location=data.get('location'),
        services=data.get('services'),
        appointment_fee=data.get('appointment_fee'),
        billing_type=data.get('billing_type'),
        repeat=data.get('repeat', False)
    )

    db.session.add(new_appointment)
    db.session.commit()
    return jsonify({"message": "Appointment created successfully", "appointment": _serialize_appointment(new_appointment)}), 201
    """Creates a new appointment."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.get_json()

    required = ['appointment_datetime']
    if any(field not in data for field in required):
        return jsonify({"error": "Missing required fields"}), 400

    doctor_id, patient_id = None, None

    # Determine who is the doctor and patient based on the creator's role
    if user.role.name == 'doctor':
        doctor_id = user.id
        patient_id = data.get('patient_id')
        if not patient_id or not user.assigned_patients.filter_by(id=patient_id).first():
            return jsonify({"error": "Patient not found or not assigned to you"}), 404
    elif user.role.name == 'patient':
        patient_id = user.id
        doctor_id = data.get('doctor_id')
        if not doctor_id or not user.assigned_doctors.filter_by(id=doctor_id).first():
            return jsonify({"error": "Doctor not found or you are not assigned to them"}), 404
    else:
        return jsonify({"error": "You do not have permission to create appointments"}), 403

    new_appointment = Appointment(
        doctor_id=doctor_id,
        patient_id=patient_id,
        appointment_datetime=datetime.fromisoformat(data['appointment_datetime']),
        duration=data.get('duration'),
        location=data.get('location'),
        services=data.get('services'),
        appointment_fee=data.get('appointment_fee'),
        billing_type=data.get('billing_type'),
        repeat=data.get('repeat', False)
    )

    db.session.add(new_appointment)
    db.session.commit()
    return jsonify({"message": "Appointment created successfully", "appointment": _serialize_appointment(new_appointment)}), 201

def get_appointments():
    """Gets all appointments for the logged-in user."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if user.role.name == 'doctor':
        appointments = user.doctor_appointments.all()
    elif user.role.name == 'patient':
        appointments = user.patient_appointments.all()
    else:
        return jsonify({"appointments": []}), 200
        
    return jsonify({"appointments": [_serialize_appointment(appt) for appt in appointments]}), 200

def get_appointment_by_id(appointment_id):
    """Gets a single appointment by its ID."""
    user_id = get_jwt_identity()
    appointment = Appointment.query.get(appointment_id)

    if not appointment or (appointment.doctor_id != user_id and appointment.patient_id != user_id):
        return jsonify({"error": "Appointment not found or you do not have permission to view it"}), 404
        
    return jsonify({"appointment": _serialize_appointment(appointment)}), 200

def update_appointment(appointment_id):
    """Updates an existing appointment."""
    user_id = get_jwt_identity()
    appointment = Appointment.query.get(appointment_id)

    if not appointment or (appointment.doctor_id != user_id and appointment.patient_id != user_id):
        return jsonify({"error": "Appointment not found or you do not have permission to edit it"}), 404

    data = request.get_json()
    for key, value in data.items():
        if key == 'appointment_datetime':
            setattr(appointment, key, datetime.fromisoformat(value))
        elif hasattr(appointment, key):
            setattr(appointment, key, value)

    db.session.commit()
    return jsonify({"message": "Appointment updated successfully", "appointment": _serialize_appointment(appointment)}), 200

def delete_appointment(appointment_id):
    """Deletes an appointment."""
    user_id = get_jwt_identity()
    appointment = Appointment.query.get(appointment_id)

    if not appointment or (appointment.doctor_id != user_id and appointment.patient_id != user_id):
        return jsonify({"error": "Appointment not found or you do not have permission to delete it"}), 404

    db.session.delete(appointment)
    db.session.commit()
    return jsonify({"message": "Appointment deleted successfully"}), 200
