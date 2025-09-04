# /app/api/controllers/clinical_notes_controller.py
import hashlib
import json
from datetime import datetime
from flask import request, jsonify
from flask_jwt_extended import get_jwt_identity
from sqlalchemy import and_, or_
from app.extensions import db
from app.models.user_models import User
from app.models.appointment_models import Appointment
from app.models.clinical_notes_models import NoteTemplate, ClinicalNote, NoteAmendment
from app.utils.encryption_util import encryptor

def get_note_templates():
    """Get all active note templates."""
    try:
        templates = NoteTemplate.query.filter_by(is_active=True).all()
        
        template_list = []
        for template in templates:
            template_list.append({
                'id': template.id,
                'name': template.name,
                'description': template.description,
                'note_type': template.note_type,
                'schema': template.schema,
                'version': template.version,
                'specialty': template.specialty,
                'created_at': template.created_at.isoformat()
            })
        
        return jsonify({'templates': template_list}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to fetch templates: {str(e)}'}), 500

def get_note_template(template_id):
    """Get a specific note template by ID."""
    try:
        template = NoteTemplate.query.get(template_id)
        if not template or not template.is_active:
            return jsonify({'error': 'Template not found'}), 404
        
        return jsonify({
            'id': template.id,
            'name': template.name,
            'description': template.description,
            'note_type': template.note_type,
            'schema': template.schema,
            'version': template.version,
            'specialty': template.specialty,
            'created_at': template.created_at.isoformat()
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to fetch template: {str(e)}'}), 500

def create_clinical_note():
    """Create a new clinical note."""
    try:
        doctor_id = get_jwt_identity()
        doctor = User.query.get(doctor_id)
        
        if not doctor or doctor.role.name != 'doctor':
            return jsonify({'error': 'Only doctors can create clinical notes'}), 403
        
        data = request.get_json()
        required_fields = ['patient_id', 'template_id', 'title', 'content']
        
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields: patient_id, template_id, title, content'}), 400
        
        # Verify patient is assigned to this doctor
        patient = doctor.assigned_patients.filter_by(id=data['patient_id']).first()
        if not patient:
            return jsonify({'error': 'Patient not found or not assigned to you'}), 404
        
        # Verify template exists
        template = NoteTemplate.query.get(data['template_id'])
        if not template or not template.is_active:
            return jsonify({'error': 'Invalid template'}), 400
        
        # Verify appointment if provided
        appointment = None
        if data.get('appointment_id'):
            appointment = Appointment.query.filter_by(
                id=data['appointment_id'],
                doctor_id=doctor_id,
                patient_id=data['patient_id']
            ).first()
            if not appointment:
                return jsonify({'error': 'Invalid appointment'}), 400
        
        # Create the clinical note
        note = ClinicalNote(
            patient_id=data['patient_id'],
            doctor_id=doctor_id,
            appointment_id=data.get('appointment_id'),
            template_id=data['template_id'],
            title=data['title'],
            note_type=template.note_type,
            status='draft'
        )
        
        # Encrypt and store content
        note.encrypt_content(data['content'])
        
        db.session.add(note)
        db.session.commit()
        
        return jsonify({
            'message': 'Clinical note created successfully',
            'note': note.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to create note: {str(e)}'}), 500

def update_clinical_note(note_id):
    """Update an existing clinical note (only if not locked)."""
    try:
        doctor_id = get_jwt_identity()
        note = ClinicalNote.query.get(note_id)
        
        if not note:
            return jsonify({'error': 'Note not found'}), 404
        
        if note.doctor_id != doctor_id:
            return jsonify({'error': 'You can only edit your own notes'}), 403
        
        if note.is_locked or note.status == 'signed':
            return jsonify({'error': 'Cannot edit locked or signed notes'}), 403
        
        data = request.get_json()
        
        # Update allowed fields
        if 'title' in data:
            note.title = data['title']
        
        if 'content' in data:
            note.encrypt_content(data['content'])
        
        if 'status' in data and data['status'] in ['draft', 'signed']:
            note.status = data['status']
        
        db.session.commit()
        
        return jsonify({
            'message': 'Note updated successfully',
            'note': note.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update note: {str(e)}'}), 500

def sign_clinical_note(note_id):
    """Sign and lock a clinical note."""
    try:
        doctor_id = get_jwt_identity()
        note = ClinicalNote.query.get(note_id)
        
        if not note:
            return jsonify({'error': 'Note not found'}), 404
        
        if note.doctor_id != doctor_id:
            return jsonify({'error': 'You can only sign your own notes'}), 403
        
        if note.status == 'signed':
            return jsonify({'error': 'Note is already signed'}), 400
        
        # Generate signature hash for integrity
        content_hash = hashlib.sha256(note.content.encode('utf-8')).hexdigest()
        
        note.status = 'signed'
        note.is_locked = True
        note.signed_at = datetime.utcnow()
        note.signed_by = doctor_id
        note.signature_hash = content_hash
        
        db.session.commit()
        
        return jsonify({
            'message': 'Note signed and locked successfully',
            'note': note.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to sign note: {str(e)}'}), 500

def get_patient_notes(patient_id):
    """Get all clinical notes for a specific patient."""
    try:
        doctor_id = get_jwt_identity()
        doctor = User.query.get(doctor_id)
        
        # Verify patient is assigned to this doctor
        patient = doctor.assigned_patients.filter_by(id=patient_id).first()
        if not patient:
            return jsonify({'error': 'Patient not found or not assigned to you'}), 404
        
        # Get notes with pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        note_type = request.args.get('type', None)
        
        query = ClinicalNote.query.filter_by(patient_id=patient_id)
        
        if note_type:
            query = query.filter_by(note_type=note_type)
        
        # Order by creation date (most recent first)
        query = query.order_by(ClinicalNote.created_at.desc())
        
        notes = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        notes_list = []
        for note in notes.items:
            note_data = note.to_dict(include_content=False)  # Don't include full content in list
            notes_list.append(note_data)
        
        return jsonify({
            'notes': notes_list,
            'pagination': {
                'page': notes.page,
                'pages': notes.pages,
                'per_page': notes.per_page,
                'total': notes.total
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to fetch notes: {str(e)}'}), 500

def get_clinical_note(note_id):
    """Get a specific clinical note with full content."""
    try:
        doctor_id = get_jwt_identity()
        note = ClinicalNote.query.get(note_id)
        
        if not note:
            return jsonify({'error': 'Note not found'}), 404
        
        # Check if doctor has access to this note
        if note.doctor_id != doctor_id:
            # Allow access if it's their patient's note from another doctor
            doctor = User.query.get(doctor_id)
            patient = doctor.assigned_patients.filter_by(id=note.patient_id).first()
            if not patient:
                return jsonify({'error': 'Access denied'}), 403
        
        return jsonify({'note': note.to_dict()}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to fetch note: {str(e)}'}), 500

def get_appointment_notes(appointment_id):
    """Get all notes associated with a specific appointment."""
    try:
        doctor_id = get_jwt_identity()
        
        # Verify appointment belongs to this doctor
        appointment = Appointment.query.filter_by(id=appointment_id, doctor_id=doctor_id).first()
        if not appointment:
            return jsonify({'error': 'Appointment not found'}), 404
        
        notes = ClinicalNote.query.filter_by(appointment_id=appointment_id).order_by(ClinicalNote.created_at.desc()).all()
        
        notes_list = [note.to_dict() for note in notes]
        
        return jsonify({'notes': notes_list}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to fetch appointment notes: {str(e)}'}), 500

def delete_clinical_note(note_id):
    """Delete a clinical note (only drafts can be deleted)."""
    try:
        doctor_id = get_jwt_identity()
        note = ClinicalNote.query.get(note_id)
        
        if not note:
            return jsonify({'error': 'Note not found'}), 404
        
        if note.doctor_id != doctor_id:
            return jsonify({'error': 'You can only delete your own notes'}), 403
        
        if note.status != 'draft':
            return jsonify({'error': 'Only draft notes can be deleted'}), 403
        
        db.session.delete(note)
        db.session.commit()
        
        return jsonify({'message': 'Note deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete note: {str(e)}'}), 500

def amend_clinical_note(note_id):
    """Add an amendment to a signed clinical note."""
    try:
        doctor_id = get_jwt_identity()
        note = ClinicalNote.query.get(note_id)
        
        if not note:
            return jsonify({'error': 'Note not found'}), 404
        
        if note.doctor_id != doctor_id:
            return jsonify({'error': 'You can only amend your own notes'}), 403
        
        if note.status != 'signed':
            return jsonify({'error': 'Only signed notes can be amended'}), 403
        
        data = request.get_json()
        required_fields = ['amendment_text', 'reason']
        
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields: amendment_text, reason'}), 400
        
        # Create amendment record
        amendment = NoteAmendment(
            original_note_id=note_id,
            amended_by=doctor_id,
            amendment_text=encryptor.encrypt(data['amendment_text']),
            reason=data['reason']
        )
        
        # Update note status
        note.status = 'amended'
        
        db.session.add(amendment)
        db.session.commit()
        
        return jsonify({
            'message': 'Amendment added successfully',
            'amendment_id': amendment.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to add amendment: {str(e)}'}), 500

def get_note_amendments(note_id):
    """Get all amendments for a clinical note."""
    try:
        doctor_id = get_jwt_identity()
        note = ClinicalNote.query.get(note_id)
        
        if not note:
            return jsonify({'error': 'Note not found'}), 404
        
        # Check if doctor has access to this note
        if note.doctor_id != doctor_id:
            # Allow access if it's their patient's note from another doctor
            doctor = User.query.get(doctor_id)
            patient = doctor.assigned_patients.filter_by(id=note.patient_id).first()
            if not patient:
                return jsonify({'error': 'Access denied'}), 403
        
        amendments = NoteAmendment.query.filter_by(original_note_id=note_id).order_by(NoteAmendment.created_at.desc()).all()
        
        amendments_list = []
        for amendment in amendments:
            amendments_list.append({
                'id': amendment.id,
                'amendment_text': encryptor.decrypt(amendment.amendment_text),
                'reason': amendment.reason,
                'amended_by': amendment.amended_by,
                'created_at': amendment.created_at.isoformat()
            })
        
        return jsonify({'amendments': amendments_list}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to fetch amendments: {str(e)}'}), 500

def search_notes():
    """Search clinical notes by content, title, or note type."""
    try:
        doctor_id = get_jwt_identity()
        doctor = User.query.get(doctor_id)
        
        # Get search parameters
        query_text = request.args.get('q', '').strip()
        patient_id = request.args.get('patient_id', type=int)
        note_type = request.args.get('type', '')
        status = request.args.get('status', '')
        date_from = request.args.get('date_from', '')
        date_to = request.args.get('date_to', '')
        
        if not query_text and not patient_id and not note_type:
            return jsonify({'error': 'At least one search parameter is required'}), 400
        
        # Base query for doctor's patients
        patient_ids = [p.id for p in doctor.assigned_patients]
        query = ClinicalNote.query.filter(ClinicalNote.patient_id.in_(patient_ids))
        
        # Apply filters
        if patient_id:
            query = query.filter_by(patient_id=patient_id)
        
        if note_type:
            query = query.filter_by(note_type=note_type)
        
        if status:
            query = query.filter_by(status=status)
        
        if date_from:
            try:
                from_date = datetime.fromisoformat(date_from)
                query = query.filter(ClinicalNote.created_at >= from_date)
            except ValueError:
                return jsonify({'error': 'Invalid date_from format'}), 400
        
        if date_to:
            try:
                to_date = datetime.fromisoformat(date_to)
                query = query.filter(ClinicalNote.created_at <= to_date)
            except ValueError:
                return jsonify({'error': 'Invalid date_to format'}), 400
        
        # Text search in title (content search would require decryption)
        if query_text:
            query = query.filter(ClinicalNote.title.ilike(f'%{query_text}%'))
        
        notes = query.order_by(ClinicalNote.created_at.desc()).limit(50).all()
        
        notes_list = [note.to_dict(include_content=False) for note in notes]
        
        return jsonify({
            'notes': notes_list,
            'count': len(notes_list)
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Search failed: {str(e)}'}), 500