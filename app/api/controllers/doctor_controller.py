# /app/api/controllers/doctor_controller.py
import secrets
import string
from flask import request, jsonify
from sqlalchemy.exc import IntegrityError
from app.extensions import db, bcrypt
from app.models.user_models import User, Role, DoctorProfile
from app.utils.encryption_util import encryptor
from app.utils.email_util import send_password_email # <-- Import the email function

def _generate_random_password(length=12):
    """Generates a secure, random password that meets complexity requirements."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        # Ensure the password meets the complexity requirements defined in the User model
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in string.punctuation for c in password)):
            break
    return password

def register_doctor():
    """Handles the logic for registering a new doctor, generating a password, and sending it via email."""
    data = request.get_json()
    
    # --- Validate required fields (password is no longer required from the user) ---
    required_user_fields = ['username', 'email', 'first_name', 'last_name']
    required_profile_fields = ['medical_license_number', 'qualifications']
    missing_fields = [f for f in required_user_fields + required_profile_fields if f not in data]
    if missing_fields:
        return jsonify({'error': f"Missing required fields: {', '.join(missing_fields)}"}), 400

    # --- Encrypt user data and check for existence ---
    encrypted_email = encryptor.encrypt(data['email'])
    encrypted_username = encryptor.encrypt(data['username'])

    # Check for uniqueness
    users = User.query.all()
    for user in users:
        if encryptor.decrypt(user.username) == data['username']:
            return jsonify({'error': 'Username already exists'}), 409
        if encryptor.decrypt(user.email) == data['email']:
            return jsonify({'error': 'Email already exists'}), 409

    # --- Create the User record ---
    doctor_role = Role.query.filter_by(name='doctor').first()
    if not doctor_role:
        return jsonify({'error': "The 'doctor' role has not been configured in the system."}), 500

    # Generate a random password
    temp_password = _generate_random_password()

    new_user = User(
        username=encrypted_username,
        email=encrypted_email,
        role_id=doctor_role.id,
        must_change_password=True # Force password change on first login
    )
    # Set the password directly, bypassing the set_password method's validation
    new_user.password_hash = bcrypt.generate_password_hash(temp_password).decode('utf-8')

    # --- Create the DoctorProfile record ---
    doctor_profile = DoctorProfile(
        user=new_user,
        first_name=encryptor.encrypt(data['first_name']),
        last_name=encryptor.encrypt(data['last_name']),
        medical_license_number=encryptor.encrypt(data['medical_license_number']),
        qualifications=encryptor.encrypt(data['qualifications']),
        npi_number=encryptor.encrypt(data.get('npi_number')) if data.get('npi_number') else None,
        dea_number=encryptor.encrypt(data.get('dea_number')) if data.get('dea_number') else None,
        profile_picture_url=encryptor.encrypt(data.get('profile_picture_url')) if data.get('profile_picture_url') else None,
        biography=encryptor.encrypt(data.get('biography')) if data.get('biography') else None,
        languages_spoken=encryptor.encrypt(data.get('languages_spoken')) if data.get('languages_spoken') else None,
        department=data.get('department'),
        specialization=data.get('specialization'),
        years_of_experience=data.get('years_of_experience'),
        available_for_telehealth=data.get('available_for_telehealth', False)
    )

    # --- Commit to database and send email ---
    try:
        db.session.add(new_user)
        db.session.add(doctor_profile)
        db.session.commit()
        
        # Send the password email after the user is successfully committed
        send_password_email(data['email'], data['username'], temp_password)

        return jsonify({'message': 'Doctor registered successfully. Credentials have been sent to their email.'}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'A database integrity error occurred. A unique value (like license number) might already exist.'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

def get_all_doctors():
    """Retrieves a list of all doctors with their decrypted profile information."""
    doctor_role = Role.query.filter_by(name='doctor').first()
    if not doctor_role:
        return jsonify({'doctors': []}), 200

    doctors = db.session.query(User, DoctorProfile).join(DoctorProfile).filter(User.role_id == doctor_role.id).all()

    doctor_list = []
    for user, profile in doctors:
        doctor_list.append({
            'user_id': user.id,
            'email': encryptor.decrypt(user.email),
            'first_name': encryptor.decrypt(profile.first_name),
            'last_name': encryptor.decrypt(profile.last_name),
            'department': profile.department,
            'specialization': profile.specialization,
            'medical_license_number': encryptor.decrypt(profile.medical_license_number),
            'qualifications': encryptor.decrypt(profile.qualifications),
            'years_of_experience': profile.years_of_experience,
            'npi_number': encryptor.decrypt(profile.npi_number),
            'dea_number': encryptor.decrypt(profile.dea_number),
            'available_for_telehealth': profile.available_for_telehealth,
            'profile_picture_url': encryptor.decrypt(profile.profile_picture_url),
            'biography': encryptor.decrypt(profile.biography),
            'languages_spoken': encryptor.decrypt(profile.languages_spoken),
            'is_active': user.is_active,
            'last_login': user.last_login.isoformat() if user.last_login else None
        })
        
    return jsonify({'doctors': doctor_list}), 200
