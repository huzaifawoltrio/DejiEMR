import secrets
import string
from flask import request, jsonify
from sqlalchemy.exc import IntegrityError
from app.extensions import db
from app.models.user_models import User, Role, DoctorProfile
from app.utils.encryption_util import encryptor
from app.utils.email_util import send_password_email
from flask_jwt_extended import jwt_required, get_jwt_identity


def _generate_random_password(length=12):
    """Generates a secure, random 12-character password with required complexity."""
    if length != 12:
        raise ValueError("Password length must be exactly 12 characters for this generator.")

    # Define character sets
    all_chars = string.ascii_letters + string.digits + string.punctuation
    
    while True:
        # Generate a random 12-character password
        password = ''.join(secrets.choice(all_chars) for _ in range(length))
        
        # Check if it meets the complexity requirements
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any(c in string.punctuation for c in password)):
            return password

def _decrypt_doctor_data(doctor_user):
    """Helper to decrypt a doctor's user and profile data for responses."""
    if not doctor_user or not doctor_user.doctor_profile:
        return None
    profile = doctor_user.doctor_profile

    def safe_decrypt(field):
        return encryptor.decrypt(field) if field else None

    decrypted_profile_picture_url = None
    if doctor_user.profile_picture_url:
        try:
            decrypted_profile_picture_url = encryptor.decrypt(doctor_user.profile_picture_url)
        except Exception:
            decrypted_profile_picture_url = None

    return {
        'user_id': doctor_user.id,
        'username': safe_decrypt(doctor_user.username),
        'email': safe_decrypt(doctor_user.email),
        'profile_picture_url': decrypted_profile_picture_url,
        'is_active': doctor_user.is_active,
        'last_login': doctor_user.last_login.isoformat() if doctor_user.last_login else None,
        'created_at': doctor_user.created_at.isoformat() if doctor_user.created_at else None,
        'updated_at': doctor_user.updated_at.isoformat() if doctor_user.updated_at else None,
        'first_name': profile.first_name,
        'last_name': profile.last_name,
        'specialization': profile.specialization,
        'medical_license_number': profile.medical_license_number,
        'qualifications': profile.qualifications,
        'npi_number': profile.npi_number,
        'dea_number': profile.dea_number,
        'biography': profile.biography,
        'languages_spoken': profile.languages_spoken,
        'department': profile.department,
        'years_of_experience': profile.years_of_experience,
        'available_for_telehealth': profile.available_for_telehealth,
    }


def register_doctor():
    data = request.get_json()
    
    required_fields = ['username', 'email', 'first_name', 'last_name', 'medical_license_number', 'qualifications']
    if any(field not in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    username = data['username']
    email = data['email']

    if User.query.filter_by(username_hash=User.create_hash(username)).first():
        return jsonify({'error': 'Username already exists'}), 409
    if User.query.filter_by(email_hash=User.create_hash(email)).first():
        return jsonify({'error': 'Email already exists'}), 409

    doctor_role = Role.query.filter_by(name='doctor').first()
    if not doctor_role:
        return jsonify({'error': "The 'doctor' role has not been configured."}), 500

    temp_password = _generate_random_password()

    new_user = User(
        username=encryptor.encrypt(username),
        email=encryptor.encrypt(email),
        username_hash=User.create_hash(username),
        email_hash=User.create_hash(email),
        role_id=doctor_role.id,
        must_change_password=True
    )
    new_user.set_password(temp_password)

    doctor_profile = DoctorProfile(
        user=new_user,
        first_name=encryptor.encrypt(data['first_name']),
        last_name=encryptor.encrypt(data['last_name']),
        medical_license_number=encryptor.encrypt(data['medical_license_number']),
        qualifications=encryptor.encrypt(data['qualifications']),
        npi_number=encryptor.encrypt(data.get('npi_number')) if data.get('npi_number') else None,
        dea_number=encryptor.encrypt(data.get('dea_number')) if data.get('dea_number') else None,
        biography=encryptor.encrypt(data.get('biography')) if data.get('biography') else None,
        languages_spoken=encryptor.encrypt(data.get('languages_spoken')) if data.get('languages_spoken') else None,
        department=data.get('department'),
        specialization=data.get('specialization'),
        years_of_experience=data.get('years_of_experience'),
        available_for_telehealth=data.get('available_for_telehealth', False)
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        send_password_email(data['email'], data['username'], temp_password)
        return jsonify({
            'message': 'Doctor registered successfully. Credentials have been sent to their email.',
            'user_id': new_user.id
        }), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'A unique value (like license number) might already exist.'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

def get_all_doctors():
    doctors = db.session.query(User, DoctorProfile).join(DoctorProfile).filter(User.role.has(name='doctor')).all()
    doctor_list = []
    for user, profile in doctors:
        doctor_list.append({
            'user_id': user.id,
            'email': encryptor.decrypt(user.email),
            'first_name': encryptor.decrypt(profile.first_name),
            'last_name': encryptor.decrypt(profile.last_name),
            'specialization': profile.specialization,
            'is_active': user.is_active,
        })
    return jsonify({'doctors': doctor_list}), 200


def get_doctor_profile():
    """
    Gets the profile details for the currently logged-in doctor.
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user or user.role.name != 'doctor':
        return jsonify({'error': 'Doctor not found or not authorized'}), 404

    profile = user.doctor_profile
    if not profile:
        return jsonify({'error': 'Doctor profile not found'}), 404

    # Decrypt and serialize the profile data
    profile_data = {
        'first_name': encryptor.decrypt(profile.first_name),
        'last_name': encryptor.decrypt(profile.last_name),
        'medical_license_number': encryptor.decrypt(profile.medical_license_number),
        'qualifications': encryptor.decrypt(profile.qualifications),
        'npi_number': encryptor.decrypt(profile.npi_number) if profile.npi_number else None,
        'dea_number': encryptor.decrypt(profile.dea_number) if profile.dea_number else None,
        'biography': encryptor.decrypt(profile.biography) if profile.biography else None,
        'languages_spoken': encryptor.decrypt(profile.languages_spoken) if profile.languages_spoken else None,
        'department': profile.department,
        'specialization': profile.specialization,
        'years_of_experience': profile.years_of_experience,
        'available_for_telehealth': profile.available_for_telehealth,
        'user_id': user.id,
        'email': encryptor.decrypt(user.email),
        'is_active': user.is_active,
    }

    return jsonify(profile_data), 200

def get_my_doctors():
    """Retrieves all doctors assigned to the logged-in patient using the ORM relationship."""
    patient_id = get_jwt_identity()
    patient = User.query.get(patient_id)

    if not patient or patient.role.name != 'patient':
        return jsonify({'error': 'Patient not found or invalid role.'}), 404

    # Use the 'assigned_doctors' relationship directly
    doctors = patient.assigned_doctors.options(
        db.joinedload(User.doctor_profile)
    ).all()

    if not doctors:
        return jsonify({'doctors': []}), 200

    decrypted_doctors = [_decrypt_doctor_data(d) for d in doctors if d.doctor_profile]

    return jsonify({'doctors': decrypted_doctors}), 200
