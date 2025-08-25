from datetime import datetime
from app.extensions import db

class PatientProfile(db.Model):
    """Model for storing comprehensive patient-specific profile information."""
    __tablename__ = 'patient_profiles'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    
    # --- Personal Information (Encrypted) ---
    first_name = db.Column(db.String(512))
    last_name = db.Column(db.String(512))
    date_of_birth = db.Column(db.String(255))
    gender = db.Column(db.String(255))
    phone_number = db.Column(db.String(255))
    address = db.Column(db.String(1024))
    city = db.Column(db.String(512))
    state = db.Column(db.String(512))
    zip_code = db.Column(db.String(255))
    
    # --- Emergency Contact (Encrypted) ---
    emergency_contact_name = db.Column(db.String(512))
    emergency_contact_phone = db.Column(db.String(255))

    # --- Insurance Information (Encrypted) ---
    insurance_provider = db.Column(db.String(512))
    policy_number = db.Column(db.String(512))
    group_number = db.Column(db.String(512))
    policy_holder_name = db.Column(db.String(512))
    policy_holder_date_of_birth = db.Column(db.String(255))
    relationship_to_patient = db.Column(db.String(255))

    # --- Medical History (Encrypted) ---
    primary_care_physician = db.Column(db.String(512))
    allergies = db.Column(db.Text)
    current_medications = db.Column(db.Text)
    previous_surgeries = db.Column(db.Text)
    family_medical_history = db.Column(db.Text)

    # --- Lifestyle Information (Encrypted) ---
    smoking_status = db.Column(db.String(255))
    alcohol_consumption = db.Column(db.String(255))
    exercise_frequency = db.Column(db.String(255))

    # --- Presenting Complaint (Encrypted) ---
    chief_complaint = db.Column(db.Text)
    symptoms_duration = db.Column(db.String(512))
    previous_treatment_for_condition = db.Column(db.Text)
    additional_notes = db.Column(db.Text)

    # --- Non-encrypted fields ---
    current_pain_level = db.Column(db.Integer) # Scale of 1-10

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', back_populates='patient_profile')
