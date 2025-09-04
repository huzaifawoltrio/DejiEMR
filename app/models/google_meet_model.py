# /app/models/google_meet_model.py
from datetime import datetime
from app.extensions import db

class Meeting(db.Model):
    """Model for storing Google Meet events linked to patients."""
    __tablename__ = 'meetings'

    id = db.Column(db.Integer, primary_key=True)
    summary = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    
    # Store attendees as a JSON array of emails (keep for backward compatibility)
    attendees = db.Column(db.JSON, nullable=False) 
    
    # Google Calendar specific fields
    meet_link = db.Column(db.String(512), nullable=False)
    event_id = db.Column(db.String(255), nullable=False, unique=True)
    
    # NEW FIELDS: Patient and Doctor relationships
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='doctor_meetings')
    patient = db.relationship('User', foreign_keys=[patient_id], backref='patient_meetings')

    def __repr__(self):
        return f'<Meeting {self.id}: {self.summary} (Doctor: {self.doctor_id}, Patient: {self.patient_id})>'

    def to_dict(self, include_patient_details=False, include_doctor_details=False):
        """Convert meeting to dictionary for API responses."""
        from app.utils.encryption_util import encryptor
        
        result = {
            'id': self.id,
            'summary': self.summary,
            'description': self.description,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'attendees': self.attendees,
            'meet_link': self.meet_link,
            'event_id': self.event_id,
            'doctor_id': self.doctor_id,
            'patient_id': self.patient_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
        
        # Add patient details if requested and available
        if include_patient_details and self.patient and self.patient.patient_profile:
            profile = self.patient.patient_profile
            result['patient_details'] = {
                'user_id': self.patient.id,
                'username': encryptor.decrypt(self.patient.username) if self.patient.username else None,
                'email': encryptor.decrypt(self.patient.email) if self.patient.email else None,
                'first_name': encryptor.decrypt(profile.first_name) if profile.first_name else None,
                'last_name': encryptor.decrypt(profile.last_name) if profile.last_name else None,
                'phone_number': encryptor.decrypt(profile.phone_number) if profile.phone_number else None,
            }
        
        # Add doctor details if requested and available
        if include_doctor_details and self.doctor and self.doctor.doctor_profile:
            profile = self.doctor.doctor_profile
            result['doctor_details'] = {
                'user_id': self.doctor.id,
                'username': encryptor.decrypt(self.doctor.username) if self.doctor.username else None,
                'email': encryptor.decrypt(self.doctor.email) if self.doctor.email else None,
                'first_name': encryptor.decrypt(profile.first_name) if profile.first_name else None,
                'last_name': encryptor.decrypt(profile.last_name) if profile.last_name else None,
                'specialization': profile.specialization,
            }
        
        return result