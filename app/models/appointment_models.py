import os
from datetime import datetime
from app.extensions import db

# Dummy data for services as a starting point
DUMMY_SERVICES = [
    "Psychotherapy Session",
    "Initial Consultation",
    "Medication Management",
    "Follow-up Visit"
]

class Appointment(db.Model):
    """Model for storing appointment details between a doctor and a patient."""
    __tablename__ = 'appointments'

    id = db.Column(db.Integer, primary_key=True)
    
    # Foreign keys to link the appointment to the doctor and patient (both are Users)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # Appointment details
    appointment_datetime = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, nullable=False, default=int(os.environ.get('DEFAULT_APPOINTMENT_DURATION', 60)))
    location = db.Column(db.String(100)) # e.g., 'Online', 'Office Location A'
    services = db.Column(db.JSON, default=lambda: DUMMY_SERVICES) # Storing list of services as JSON
    appointment_fee = db.Column(db.Float)
    billing_type = db.Column(db.String(50)) # e.g., 'self-pay', 'insurance'
    repeat = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(50), default='Scheduled') # e.g., 'Scheduled', 'Completed', 'Cancelled'

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships to the User model
    doctor = db.relationship('User', foreign_keys=[doctor_id], back_populates='doctor_appointments')
    patient = db.relationship('User', foreign_keys=[patient_id], back_populates='patient_appointments')