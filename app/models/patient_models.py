from datetime import datetime
from app.extensions import db

class Patient(db.Model):
    """Model for storing encrypted patient information."""
    __tablename__ = 'patients'

    id = db.Column(db.Integer, primary_key=True)
    
    # Foreign key to the doctor (User) who created this patient record
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # --- Encrypted Patient PII ---
    # All sensitive data is stored as encrypted strings.
    full_name = db.Column(db.String(512), nullable=False)
    date_of_birth = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.String(255))
    email = db.Column(db.String(512), unique=True, nullable=False)
    phone_number = db.Column(db.String(255))
    address = db.Column(db.String(1024))
    presenting_problem = db.Column(db.Text)
    
    # --- Non-encrypted fields ---
    billing_type = db.Column(db.String(50)) # e.g., 'self-pay', 'insurance'
    age = db.Column(db.Integer) # This can be derived, but storing it can be useful for queries.

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship to the User model (the doctor)
    doctor = db.relationship('User', back_populates='patients')

