import secrets
import string
from flask import request, jsonify
from sqlalchemy.exc import IntegrityError
from app.extensions import db
from app.models.user_models import User, Role, DoctorProfile
from app.utils.encryption_util import encryptor
from app.utils.email_util import send_password_email

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
        profile_picture_url=encryptor.encrypt(data.get('profile_picture_url')) if data.get('profile_picture_url') else None,
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
