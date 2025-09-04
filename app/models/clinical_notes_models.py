# /app/models/clinical_notes_models.py
from datetime import datetime
from app.extensions import db
from app.utils.encryption_util import encryptor

class NoteTemplate(db.Model):
    """Model for storing clinical note templates with JSON schema for dynamic forms."""
    __tablename__ = 'note_templates'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    note_type = db.Column(db.String(50), nullable=False)  # 'progress', 'discharge', 'assessment', etc.
    
    # JSON schema defining the form structure
    schema = db.Column(db.JSON, nullable=False)
    
    # Template metadata
    is_active = db.Column(db.Boolean, default=True)
    version = db.Column(db.String(10), default='1.0')
    specialty = db.Column(db.String(50))  # Optional: specific to certain specialties
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Relationships
    clinical_notes = db.relationship('ClinicalNote', backref='template', lazy='dynamic')
    creator = db.relationship('User', backref='created_templates')

class ClinicalNote(db.Model):
    """Model for storing clinical notes with encrypted content."""
    __tablename__ = 'clinical_notes'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Foreign keys
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id'), nullable=True)
    template_id = db.Column(db.Integer, db.ForeignKey('note_templates.id'), nullable=False)
    
    # Note metadata
    title = db.Column(db.String(200), nullable=False)
    note_type = db.Column(db.String(50), nullable=False)
    
    # Encrypted note content (JSON format matching template schema)
    content = db.Column(db.Text, nullable=False)  # Encrypted JSON
    
    # Status and versioning
    status = db.Column(db.String(20), default='draft')  # 'draft', 'signed', 'amended'
    is_locked = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    signed_at = db.Column(db.DateTime)
    
    # Digital signature info
    signed_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    signature_hash = db.Column(db.String(255))  # For integrity verification
    
    # Relationships
    patient = db.relationship('User', foreign_keys=[patient_id], backref='clinical_notes_as_patient')
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='clinical_notes_as_doctor')
    appointment = db.relationship('Appointment', backref='clinical_notes')
    signer = db.relationship('User', foreign_keys=[signed_by], backref='signed_notes')
    
    def encrypt_content(self, content_dict):
        """Encrypt note content as JSON string."""
        import json
        self.content = encryptor.encrypt(json.dumps(content_dict))
    
    def decrypt_content(self):
        """Decrypt and return note content as dictionary."""
        import json
        try:
            decrypted = encryptor.decrypt(self.content)
            return json.loads(decrypted) if decrypted else {}
        except Exception:
            return {}
    
    def to_dict(self, include_content=True):
        """Serialize note for API responses."""
        result = {
            'id': self.id,
            'patient_id': self.patient_id,
            'doctor_id': self.doctor_id,
            'appointment_id': self.appointment_id,
            'template_id': self.template_id,
            'title': self.title,
            'note_type': self.note_type,
            'status': self.status,
            'is_locked': self.is_locked,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'signed_at': self.signed_at.isoformat() if self.signed_at else None,
            'template_name': self.template.name if self.template else None,
        }
        
        if include_content:
            result['content'] = self.decrypt_content()
            
        return result

class NoteAmendment(db.Model):
    """Model for tracking amendments to signed notes (audit trail)."""
    __tablename__ = 'note_amendments'
    
    id = db.Column(db.Integer, primary_key=True)
    original_note_id = db.Column(db.Integer, db.ForeignKey('clinical_notes.id'), nullable=False)
    amended_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Encrypted amendment content
    amendment_text = db.Column(db.Text, nullable=False)  # Encrypted
    reason = db.Column(db.String(200), nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    original_note = db.relationship('ClinicalNote', backref='amendments')
    amender = db.relationship('User', backref='note_amendments')

# Default templates data for initialization
DEFAULT_TEMPLATES = [
    {
        'name': 'Simple Progress Note (SOAP)',
        'description': 'Standard SOAP format progress note',
        'note_type': 'progress',
        'schema': {
            'sections': [
                {
                    'title': 'Subjective',
                    'fields': [
                        {
                            'name': 'chief_complaint',
                            'label': 'Chief Complaint',
                            'type': 'text',
                            'required': True,
                            'placeholder': 'Patient\'s primary concern or reason for visit'
                        },
                        {
                            'name': 'history_present_illness',
                            'label': 'History of Present Illness',
                            'type': 'textarea',
                            'required': True,
                            'rows': 4
                        },
                        {
                            'name': 'review_of_systems',
                            'label': 'Review of Systems',
                            'type': 'textarea',
                            'required': False,
                            'rows': 3
                        }
                    ]
                },
                {
                    'title': 'Objective',
                    'fields': [
                        {
                            'name': 'vital_signs',
                            'label': 'Vital Signs',
                            'type': 'object',
                            'fields': [
                                {'name': 'blood_pressure', 'label': 'Blood Pressure', 'type': 'text', 'placeholder': '120/80'},
                                {'name': 'heart_rate', 'label': 'Heart Rate', 'type': 'number', 'placeholder': 'BPM'},
                                {'name': 'temperature', 'label': 'Temperature', 'type': 'text', 'placeholder': '98.6°F'},
                                {'name': 'respiratory_rate', 'label': 'Respiratory Rate', 'type': 'number', 'placeholder': 'per minute'},
                                {'name': 'oxygen_saturation', 'label': 'O2 Saturation', 'type': 'text', 'placeholder': '98%'}
                            ]
                        },
                        {
                            'name': 'physical_exam',
                            'label': 'Physical Examination',
                            'type': 'textarea',
                            'required': True,
                            'rows': 5
                        }
                    ]
                },
                {
                    'title': 'Assessment',
                    'fields': [
                        {
                            'name': 'assessment',
                            'label': 'Clinical Assessment',
                            'type': 'textarea',
                            'required': True,
                            'rows': 4,
                            'placeholder': 'Diagnosis, differential diagnosis, clinical impression'
                        }
                    ]
                },
                {
                    'title': 'Plan',
                    'fields': [
                        {
                            'name': 'treatment_plan',
                            'label': 'Treatment Plan',
                            'type': 'textarea',
                            'required': True,
                            'rows': 4
                        },
                        {
                            'name': 'follow_up',
                            'label': 'Follow-up Instructions',
                            'type': 'textarea',
                            'required': False,
                            'rows': 2
                        }
                    ]
                }
            ]
        }
    },
    {
        'name': 'Discharge Summary Note',
        'description': 'Comprehensive discharge summary for hospital stays',
        'note_type': 'discharge',
        'schema': {
            'sections': [
                {
                    'title': 'Admission Information',
                    'fields': [
                        {
                            'name': 'admission_date',
                            'label': 'Admission Date',
                            'type': 'date',
                            'required': True
                        },
                        {
                            'name': 'discharge_date',
                            'label': 'Discharge Date',
                            'type': 'date',
                            'required': True
                        },
                        {
                            'name': 'length_of_stay',
                            'label': 'Length of Stay (days)',
                            'type': 'number',
                            'required': False
                        }
                    ]
                },
                {
                    'title': 'Clinical Summary',
                    'fields': [
                        {
                            'name': 'admitting_diagnosis',
                            'label': 'Admitting Diagnosis',
                            'type': 'text',
                            'required': True
                        },
                        {
                            'name': 'discharge_diagnosis',
                            'label': 'Discharge Diagnosis',
                            'type': 'text',
                            'required': True
                        },
                        {
                            'name': 'hospital_course',
                            'label': 'Hospital Course',
                            'type': 'textarea',
                            'required': True,
                            'rows': 6
                        }
                    ]
                },
                {
                    'title': 'Medications and Instructions',
                    'fields': [
                        {
                            'name': 'discharge_medications',
                            'label': 'Discharge Medications',
                            'type': 'textarea',
                            'required': True,
                            'rows': 4
                        },
                        {
                            'name': 'follow_up_plan',
                            'label': 'Follow-up Plan',
                            'type': 'textarea',
                            'required': True,
                            'rows': 3
                        },
                        {
                            'name': 'activity_restrictions',
                            'label': 'Activity Restrictions',
                            'type': 'textarea',
                            'required': False,
                            'rows': 2
                        }
                    ]
                }
            ]
        }
    },
    {
        'name': 'Initial Assessment (Adult)',
        'description': 'Comprehensive initial assessment for adult patients',
        'note_type': 'assessment',
        'schema': {
            'sections': [
                {
                    'title': 'Chief Complaint & History',
                    'fields': [
                        {
                            'name': 'chief_complaint',
                            'label': 'Chief Complaint',
                            'type': 'text',
                            'required': True
                        },
                        {
                            'name': 'history_present_illness',
                            'label': 'History of Present Illness',
                            'type': 'textarea',
                            'required': True,
                            'rows': 5
                        },
                        {
                            'name': 'past_medical_history',
                            'label': 'Past Medical History',
                            'type': 'textarea',
                            'required': True,
                            'rows': 3
                        },
                        {
                            'name': 'past_surgical_history',
                            'label': 'Past Surgical History',
                            'type': 'textarea',
                            'required': False,
                            'rows': 2
                        }
                    ]
                },
                {
                    'title': 'Social & Family History',
                    'fields': [
                        {
                            'name': 'social_history',
                            'label': 'Social History',
                            'type': 'textarea',
                            'required': True,
                            'rows': 3,
                            'placeholder': 'Smoking, alcohol, drugs, occupation, living situation'
                        },
                        {
                            'name': 'family_history',
                            'label': 'Family History',
                            'type': 'textarea',
                            'required': True,
                            'rows': 3
                        }
                    ]
                },
                {
                    'title': 'Medications & Allergies',
                    'fields': [
                        {
                            'name': 'current_medications',
                            'label': 'Current Medications',
                            'type': 'textarea',
                            'required': True,
                            'rows': 4
                        },
                        {
                            'name': 'allergies',
                            'label': 'Allergies',
                            'type': 'textarea',
                            'required': True,
                            'rows': 2,
                            'placeholder': 'Drug allergies, food allergies, environmental allergies'
                        }
                    ]
                }
            ]
        }
    },
    {
        'name': 'Revisit / Follow-up Note',
        'description': 'Follow-up visit note template',
        'note_type': 'followup',
        'schema': {
            'sections': [
                {
                    'title': 'Interval History',
                    'fields': [
                        {
                            'name': 'interval_history',
                            'label': 'Interval History',
                            'type': 'textarea',
                            'required': True,
                            'rows': 4,
                            'placeholder': 'Changes since last visit, compliance with treatment'
                        },
                        {
                            'name': 'current_complaints',
                            'label': 'Current Complaints',
                            'type': 'textarea',
                            'required': False,
                            'rows': 3
                        }
                    ]
                },
                {
                    'title': 'Current Status',
                    'fields': [
                        {
                            'name': 'vital_signs',
                            'label': 'Vital Signs',
                            'type': 'object',
                            'fields': [
                                {'name': 'blood_pressure', 'label': 'Blood Pressure', 'type': 'text'},
                                {'name': 'heart_rate', 'label': 'Heart Rate', 'type': 'number'},
                                {'name': 'weight', 'label': 'Weight', 'type': 'text'},
                                {'name': 'temperature', 'label': 'Temperature', 'type': 'text'}
                            ]
                        },
                        {
                            'name': 'physical_exam_changes',
                            'label': 'Physical Exam Changes',
                            'type': 'textarea',
                            'required': False,
                            'rows': 3,
                            'placeholder': 'Focus on changes from baseline or areas of concern'
                        }
                    ]
                },
                {
                    'title': 'Assessment & Plan',
                    'fields': [
                        {
                            'name': 'assessment',
                            'label': 'Assessment',
                            'type': 'textarea',
                            'required': True,
                            'rows': 3,
                            'placeholder': 'Current status, response to treatment, changes in condition'
                        },
                        {
                            'name': 'updated_plan',
                            'label': 'Updated Treatment Plan',
                            'type': 'textarea',
                            'required': True,
                            'rows': 4,
                            'placeholder': 'Medication changes, new interventions, continued treatments'
                        },
                        {
                            'name': 'next_follow_up',
                            'label': 'Next Follow-up',
                            'type': 'text',
                            'required': False,
                            'placeholder': 'When to return, specific monitoring needed'
                        }
                    ]
                }
            ]
        }
    }
]