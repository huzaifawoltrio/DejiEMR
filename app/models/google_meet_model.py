# /app/models/google_meet_model.py
from datetime import datetime
from app.extensions import db

class Meeting(db.Model):
    """Model for storing Google Meet events."""
    __tablename__ = 'meetings'

    id = db.Column(db.Integer, primary_key=True)
    summary = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    
    # Store attendees as a JSON array of emails
    attendees = db.Column(db.JSON, nullable=False) 
    
    # Google Calendar specific fields
    meet_link = db.Column(db.String(512), nullable=False)
    event_id = db.Column(db.String(255), nullable=False, unique=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Meeting {self.id}: {self.summary}>'