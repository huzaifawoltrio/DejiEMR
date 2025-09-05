# /app/models/patient_document_models.py
from datetime import datetime
from app.extensions import db

class PatientDocument(db.Model):
    """Model for storing patient document metadata and Cloudinary references."""
    __tablename__ = 'patient_documents'

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # File metadata
    file_name = db.Column(db.String(255), nullable=False)
    file_url = db.Column(db.String(1024), nullable=False)  # Cloudinary secure_url
    file_type = db.Column(db.String(50), nullable=False)   # e.g., 'pdf', 'jpg', 'png'
    file_size = db.Column(db.Integer, nullable=False)      # Size in bytes
    cloudinary_public_id = db.Column(db.String(255), nullable=False)  # For deletion
    

    
    # Document details
    description = db.Column(db.Text)
    tags = db.Column(db.Text)  # Comma-separated string
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    patient = db.relationship('User', foreign_keys=[patient_id], backref='documents')
    uploader = db.relationship('User', foreign_keys=[uploaded_by], backref='uploaded_documents')

    def to_dict(self):
        """Convert document to dictionary for API responses."""
        return {
            'id': self.id,
            'patient_id': self.patient_id,
            'uploaded_by': self.uploaded_by,
            'file_name': self.file_name,
            'file_url': self.file_url,
            'file_type': self.file_type,
            'file_size': self.file_size,
            'description': self.description,
            'tags': self.tags.split(',') if self.tags else [],
            'created_at': self.created_at.strftime('%m/%d/%Y') if self.created_at else None,
            'uploader_name': self._get_uploader_name()
        }
    
    def _get_uploader_name(self):
        """Get uploader's name for display."""
        if not self.uploader:
            return 'Unknown'
        
        from app.utils.encryption_util import encryptor
        
        try:
            if self.uploader.role.name == 'doctor' and self.uploader.doctor_profile:
                first = encryptor.decrypt(self.uploader.doctor_profile.first_name) or ''
                last = encryptor.decrypt(self.uploader.doctor_profile.last_name) or ''
                return f"Dr. {first} {last}".strip()
            elif self.uploader.role.name == 'patient' and self.uploader.patient_profile:
                first = encryptor.decrypt(self.uploader.patient_profile.first_name) or ''
                last = encryptor.decrypt(self.uploader.patient_profile.last_name) or ''
                return f"{first} {last}".strip()
            else:
                username = encryptor.decrypt(self.uploader.username)
                return username or 'Unknown'
        except Exception:
            return 'Unknown'

    @property
    def tags_list(self):
        """Get tags as a list."""
        return self.tags.split(',') if self.tags else []
    
    def set_tags(self, tags_list):
        """Set tags from a list."""
        if isinstance(tags_list, list):
            # Clean tags: strip whitespace and filter empty strings
            clean_tags = [tag.strip() for tag in tags_list if tag.strip()]
            self.tags = ','.join(clean_tags)
        else:
            self.tags = str(tags_list) if tags_list else ''

    def __repr__(self):
        return f'<PatientDocument {self.id}: {self.file_name} for Patient {self.patient_id}>'

    @classmethod
    def get_by_patient(cls, patient_id):
        """Get all documents for a specific patient, ordered by creation date."""
        return cls.query.filter_by(patient_id=patient_id).order_by(cls.created_at.desc()).all()
    
    @classmethod
    def search_documents(cls, patient_ids=None, file_type=None, tags=None, search_query=None):
        """Search documents with various filters."""
        query = cls.query
        
        if patient_ids:
            if isinstance(patient_ids, list):
                query = query.filter(cls.patient_id.in_(patient_ids))
            else:
                query = query.filter(cls.patient_id == patient_ids)
        
        if file_type:
            query = query.filter(cls.file_type.ilike(f'%{file_type}%'))
        
        if tags:
            if isinstance(tags, list):
                for tag in tags:
                    if tag.strip():
                        query = query.filter(cls.tags.ilike(f'%{tag.strip()}%'))
            else:
                query = query.filter(cls.tags.ilike(f'%{tags}%'))
        
        if search_query:
            from sqlalchemy import or_
            search_filter = or_(
                cls.file_name.ilike(f'%{search_query}%'),
                cls.description.ilike(f'%{search_query}%')
            )
            query = query.filter(search_filter)
        
        return query.order_by(cls.created_at.desc()).all()

    def get_file_size_formatted(self):
        """Return formatted file size string."""
        if not self.file_size:
            return 'Unknown'
        
        size = self.file_size
        units = ['B', 'KB', 'MB', 'GB']
        unit_index = 0
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        return f"{size:.1f} {units[unit_index]}"

    def is_image(self):
        """Check if the document is an image file."""
        image_types = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp']
        return self.file_type.lower() in image_types

    def is_pdf(self):
        """Check if the document is a PDF file."""
        return self.file_type.lower() == 'pdf'

    def is_document(self):
        """Check if the document is a text document."""
        doc_types = ['doc', 'docx', 'txt', 'rtf', 'odt']
        return self.file_type.lower() in doc_types