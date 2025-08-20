from datetime import datetime
from app.extensions import db

class PatientProfile(db.Model):
    """Model for storing patient-specific profile information."""
    __tablename__ = 'patient_profiles'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    
    # --- Encrypted Patient PII ---
    full_name = db.Column(db.String(512), nullable=False)
    date_of_birth = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(255))
    phone_number = db.Column(db.String(255))
    address = db.Column(db.String(1024))
    presenting_problem = db.Column(db.Text)
    
    # --- Non-encrypted fields ---
    billing_type = db.Column(db.String(50))
    age = db.Column(db.Integer)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # CORRECTED: Use back_populates to link to the 'patient_profile' property on User
    user = db.relationship('User', back_populates='patient_profile')
