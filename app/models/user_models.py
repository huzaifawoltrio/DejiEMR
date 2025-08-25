import hashlib
from datetime import datetime, timedelta
from app.extensions import db, bcrypt
from app.utils.encryption_util import encryptor

# --- Association tables ---
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True)
)

doctor_patient_association = db.Table('doctor_patient_association',
    db.Column('doctor_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('patient_id', db.Integer, db.ForeignKey('users.id'), primary_key=True)
)

class User(db.Model):
    """User model with HIPAA-compliant fields and hashed lookups."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    username_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked = db.Column(db.Boolean, default=False)
    account_locked_until = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    must_change_password = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    
    # Profile picture fields
    profile_picture_url = db.Column(db.String(1024))  # Encrypted Cloudinary URL
    profile_picture_public_id = db.Column(db.String(1024)) # Encrypted Cloudinary public_id

    # --- Relationships ---
    role = db.relationship('Role', backref='users')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')
    doctor_profile = db.relationship('DoctorProfile', backref='user', uselist=False, cascade="all, delete-orphan")
    patient_profile = db.relationship('PatientProfile', back_populates='user', uselist=False, cascade="all, delete-orphan")
    
    assigned_patients = db.relationship(
        'User', 
        secondary=doctor_patient_association,
        primaryjoin=(doctor_patient_association.c.doctor_id == id),
        secondaryjoin=(doctor_patient_association.c.patient_id == id),
        backref=db.backref('assigned_doctors', lazy='dynamic'),
        lazy='dynamic'
    )

    doctor_appointments = db.relationship(
        'Appointment', 
        foreign_keys='Appointment.doctor_id', 
        back_populates='doctor', 
        lazy='dynamic', 
        cascade="all, delete-orphan"
    )
    patient_appointments = db.relationship(
        'Appointment', 
        foreign_keys='Appointment.patient_id', 
        back_populates='patient', 
        lazy='dynamic', 
        cascade="all, delete-orphan"
    )

    @staticmethod
    def create_hash(value: str) -> str:
        """Creates a SHA-256 hash for a given string."""
        if not value:
            return ""
        return hashlib.sha256(value.lower().encode('utf-8')).hexdigest()

    def set_password(self, password: str) -> None:
        """Hashes and sets the user's password, enforcing complexity rules."""
        if not self._validate_password_strength(password):
            raise ValueError("Password does not meet complexity requirements")
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.password_changed_at = datetime.utcnow()
    
    def check_password(self, password: str) -> bool:
        """Checks a password and handles login attempt logic."""
        if self.account_locked and self.account_locked_until and datetime.utcnow() < self.account_locked_until:
            return False
        elif self.account_locked:
            self.account_locked = False
            self.account_locked_until = None
            self.failed_login_attempts = 0

        is_valid = bcrypt.check_password_hash(self.password_hash, password)
        
        if not is_valid:
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= 5:
                self.account_locked = True
                self.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
        else:
            self.failed_login_attempts = 0
            self.last_login = datetime.utcnow()
        
        db.session.commit()
        return is_valid

    def to_dict(self):
        """Serializes the User object to a dictionary for API responses."""
        
        profile_data = {}
        if self.role.name == 'doctor' and self.doctor_profile:
            profile_data = {
                'first_name': self.doctor_profile.first_name,
                'last_name': self.doctor_profile.last_name,
                'specialization': self.doctor_profile.specialization,
            }
        elif self.role.name == 'patient' and self.patient_profile:
            profile_data = {
                'first_name': self.patient_profile.first_name,
                'last_name': self.patient_profile.last_name,
                'date_of_birth': self.patient_profile.date_of_birth.isoformat() if self.patient_profile.date_of_birth else None
            }

        decrypted_url = None
        if self.profile_picture_url:
            try:
                decrypted_url = encryptor.decrypt(self.profile_picture_url)
            except Exception:
                decrypted_url = None # Handle case where decryption fails

        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role.name if self.role else None,
            'is_active': self.is_active,
            'profile_picture_url': decrypted_url,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            **profile_data
        }

    @staticmethod
    def _validate_password_strength(password: str) -> bool:
        """Validates that a password meets the required complexity."""
        return (len(password) >= 12 and
                any(c.isupper() for c in password) and
                any(c.islower() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password))

class DoctorProfile(db.Model):
    """Model for storing doctor-specific profile information."""
    __tablename__ = 'doctor_profiles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    first_name = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    medical_license_number = db.Column(db.String(255), nullable=False, unique=True)
    qualifications = db.Column(db.Text, nullable=False)
    npi_number = db.Column(db.String(255), unique=True)
    dea_number = db.Column(db.String(255), unique=True)
    biography = db.Column(db.Text)
    languages_spoken = db.Column(db.String(255))
    department = db.Column(db.String(100))
    specialization = db.Column(db.String(100))
    years_of_experience = db.Column(db.Integer)
    available_for_telehealth = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Role(db.Model):
    """Model for user roles."""
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    permissions = db.relationship('Permission', secondary=role_permissions, backref='roles')

class Permission(db.Model):
    """Model for granular permissions."""
    __tablename__ = 'permissions'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    resource = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255))
