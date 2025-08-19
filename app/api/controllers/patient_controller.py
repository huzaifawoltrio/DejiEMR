# /app/api/controllers/patient_controller.py
from flask import jsonify

def get_all_patients():
    """Returns a list of patients (placeholder)."""
    return jsonify({'message': 'Patient list (placeholder)', 'total': 0}), 200