# /app/api/controllers/patient_document_controller.py
from flask import request, jsonify
from flask_jwt_extended import get_jwt_identity
from app.extensions import db
from app.models.user_models import User
from app.models.patient_document_models import PatientDocument
from app.utils.cloudinary_util import cloudinary_manager
from sqlalchemy import or_, and_
import os

def upload_patient_document():
    """Upload a document for a patient."""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    # Get form data
    patient_id = request.form.get('patient_id')
    description = request.form.get('description', '')
    tags = request.form.get('tags', '')
    
    if not patient_id:
        return jsonify({'error': 'patient_id is required'}), 400
    
    # Validate patient exists and user has access
    patient = User.query.get(patient_id)
    if not patient or patient.role.name != 'patient':
        return jsonify({'error': 'Invalid patient ID'}), 400
    
    # Check permissions: doctors can upload for their patients, patients can upload for themselves
    has_permission = False
    
    # Add some debugging info
    from flask import current_app
    current_app.logger.info(f"Upload attempt: User {current_user_id} (role: {current_user.role.name}) trying to upload for patient {patient_id}")
    
    if current_user.role.name == 'doctor':
        # Check if patient is assigned to this doctor
        is_assigned_patient = current_user.assigned_patients.filter_by(id=patient_id).first()
        current_app.logger.info(f"Doctor check: Patient {patient_id} assigned to doctor {current_user_id}? {bool(is_assigned_patient)}")
        has_permission = bool(is_assigned_patient)
        if not has_permission:
            return jsonify({'error': 'Patient not assigned to you'}), 403
    elif current_user.role.name == 'patient':
        # Patients can only upload for themselves
        has_permission = int(current_user_id) == int(patient_id)
        current_app.logger.info(f"Patient check: User {current_user_id} uploading for patient {patient_id}? Match: {has_permission}")
        if not has_permission:
            return jsonify({'error': 'Can only upload documents for yourself'}), 403
    elif current_user.role.name in ['admin', 'superadmin']:
        # Admins can upload for any patient
        has_permission = True
        current_app.logger.info(f"Admin access granted for user {current_user_id}")
    else:
        current_app.logger.info(f"Permission denied for role: {current_user.role.name}")
        return jsonify({'error': 'Permission denied'}), 403
    
    # Check for file
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Upload to Cloudinary
    upload_result = cloudinary_manager.upload_patient_document(
        file, patient_id, current_user_id, description
    )
    
    if not upload_result['success']:
        return jsonify({'error': upload_result['error']}), 400
    
    # Save document metadata to database
    try:
        document = PatientDocument(
            patient_id=patient_id,
            uploaded_by=current_user_id,
            file_name=file.filename,
            file_url=upload_result['url'],
            file_type=upload_result['format'],
            file_size=upload_result['bytes'],
            cloudinary_public_id=upload_result['public_id'],
            description=description,
            tags=tags
        )
        
        db.session.add(document)
        db.session.commit()
        
        return jsonify({
            'message': 'Document uploaded successfully',
            'document': document.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        # Clean up uploaded file if database save fails
        try:
            cloudinary_manager.delete_patient_document(upload_result['public_id'])
        except Exception:
            pass
        
        return jsonify({'error': f'Failed to save document metadata: {str(e)}'}), 500

def get_patient_documents(patient_id):
    """Get all documents for a specific patient."""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    # Validate patient exists
    patient = User.query.get(patient_id)
    if not patient or patient.role.name != 'patient':
        return jsonify({'error': 'Invalid patient ID'}), 400
    
    # Check permissions
    if current_user.role.name == 'doctor':
        is_assigned_patient = current_user.assigned_patients.filter_by(id=patient_id).first()
        if not is_assigned_patient:
            return jsonify({'error': 'Patient not assigned to you'}), 403
    elif current_user.role.name == 'patient':
        if int(current_user_id) != int(patient_id):
            return jsonify({'error': 'Can only view your own documents'}), 403
    elif current_user.role.name not in ['admin', 'superadmin']:
        return jsonify({'error': 'Permission denied'}), 403
    
    # Get documents
    documents = PatientDocument.query.filter_by(patient_id=patient_id).order_by(
        PatientDocument.created_at.desc()
    ).all()
    
    return jsonify({
        'documents': [doc.to_dict() for doc in documents],
        'count': len(documents)
    }), 200

def delete_patient_document(document_id):
    """Delete a patient document."""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    # Find document
    document = PatientDocument.query.get(document_id)
    if not document:
        return jsonify({'error': 'Document not found'}), 404
    
    # Check permissions
    can_delete = False
    
    if current_user.role.name == 'doctor':
        # Doctor can delete if patient is assigned to them
        is_assigned_patient = current_user.assigned_patients.filter_by(id=document.patient_id).first()
        can_delete = bool(is_assigned_patient)
    elif current_user.role.name == 'patient':
        # Patient can delete their own documents
        can_delete = int(current_user_id) == int(document.patient_id)
    elif current_user.role.name in ['admin', 'superadmin']:
        can_delete = True
    
    if not can_delete:
        return jsonify({'error': 'Permission denied'}), 403
    
    # Delete from Cloudinary
    delete_result = cloudinary_manager.delete_patient_document(document.cloudinary_public_id)
    if not delete_result['success']:
        return jsonify({'error': 'Failed to delete file from cloud storage'}), 500
    
    # Delete from database
    try:
        db.session.delete(document)
        db.session.commit()
        
        return jsonify({'message': 'Document deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete document: {str(e)}'}), 500

def search_patient_documents():
    """Search/filter patient documents."""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    # Get query parameters
    patient_id = request.args.get('patient_id')
    file_type = request.args.get('file_type')
    tags = request.args.get('tags')  # Comma-separated
    search_query = request.args.get('q')  # General search in description/filename
    
    # Base query
    query = PatientDocument.query
    
    # Filter by patient if specified
    if patient_id:
        # Validate patient access
        patient = User.query.get(patient_id)
        if not patient or patient.role.name != 'patient':
            return jsonify({'error': 'Invalid patient ID'}), 400
        
        # Check permissions for this specific patient
        if current_user.role.name == 'doctor':
            is_assigned_patient = current_user.assigned_patients.filter_by(id=patient_id).first()
            if not is_assigned_patient:
                return jsonify({'error': 'Patient not assigned to you'}), 403
        elif current_user.role.name == 'patient':
            if int(current_user_id) != int(patient_id):
                return jsonify({'error': 'Can only search your own documents'}), 403
        elif current_user.role.name not in ['admin', 'superadmin']:
            return jsonify({'error': 'Permission denied'}), 403
        
        query = query.filter(PatientDocument.patient_id == patient_id)
    else:
        # If no specific patient, filter based on user role
        if current_user.role.name == 'doctor':
            # Get all patients assigned to this doctor
            assigned_patient_ids = [p.id for p in current_user.assigned_patients]
            if assigned_patient_ids:
                query = query.filter(PatientDocument.patient_id.in_(assigned_patient_ids))
            else:
                # No assigned patients, return empty result
                return jsonify({'documents': [], 'count': 0}), 200
        elif current_user.role.name == 'patient':
            # Patient can only see their own documents
            query = query.filter(PatientDocument.patient_id == current_user_id)
        elif current_user.role.name not in ['admin', 'superadmin']:
            return jsonify({'error': 'Permission denied'}), 403
    
    # Apply filters
    if file_type:
        query = query.filter(PatientDocument.file_type.ilike(f'%{file_type}%'))
    
    if tags:
        tag_list = [tag.strip() for tag in tags.split(',')]
        for tag in tag_list:
            if tag:
                query = query.filter(PatientDocument.tags.ilike(f'%{tag}%'))
    
    if search_query:
        search_filter = or_(
            PatientDocument.file_name.ilike(f'%{search_query}%'),
            PatientDocument.description.ilike(f'%{search_query}%')
        )
        query = query.filter(search_filter)
    
    # Execute query
    documents = query.order_by(PatientDocument.created_at.desc()).all()
    
    return jsonify({
        'documents': [doc.to_dict() for doc in documents],
        'count': len(documents),
        'filters': {
            'patient_id': patient_id,
            'file_type': file_type,
            'tags': tags,
            'search_query': search_query
        }
    }), 200

def get_document_by_id(document_id):
    """Get a specific document by ID."""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    
    if not current_user:
        return jsonify({'error': 'User not found'}), 404
    
    document = PatientDocument.query.get(document_id)
    if not document:
        return jsonify({'error': 'Document not found'}), 404
    
    # Check permissions
    can_view = False
    
    if current_user.role.name == 'doctor':
        is_assigned_patient = current_user.assigned_patients.filter_by(id=document.patient_id).first()
        can_view = bool(is_assigned_patient)
    elif current_user.role.name == 'patient':
        can_view = int(current_user_id) == int(document.patient_id)
    elif current_user.role.name in ['admin', 'superadmin']:
        can_view = True
    
    if not can_view:
        return jsonify({'error': 'Permission denied'}), 403
    
    return jsonify({'document': document.to_dict()}), 200