# /app/api/controllers/chat_controller.py
from flask import request, jsonify
from flask_jwt_extended import get_jwt_identity
from sqlalchemy import or_, and_, desc
from app.extensions import db
from app.models.user_models import User
from app.models.chat_models import ChatMessage, ChatRoom
from app.utils.encryption_util import encryptor
from app.socket_handlers.chat_handler import is_user_online, can_users_chat
from datetime import datetime

def get_chat_history():
    """Get chat history between current user and another user."""
    try:
        current_user_id = int(get_jwt_identity())
        other_user_id = request.args.get('user_id', type=int)
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        if not other_user_id:
            return jsonify({'error': 'user_id parameter is required'}), 400
        
        current_user = User.query.get(current_user_id)
        other_user = User.query.get(other_user_id)
        
        if not current_user or not other_user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if users can chat
        if not can_users_chat(current_user, other_user):
            return jsonify({'error': 'You are not authorized to chat with this user'}), 403
        
        # Query messages between the two users
        messages_query = ChatMessage.query.filter(
            or_(
                and_(ChatMessage.sender_id == current_user_id, ChatMessage.recipient_id == other_user_id),
                and_(ChatMessage.sender_id == other_user_id, ChatMessage.recipient_id == current_user_id)
            )
        ).filter(
            # Don't show deleted messages
            or_(
                and_(ChatMessage.sender_id == current_user_id, ChatMessage.is_deleted_by_sender == False),
                and_(ChatMessage.recipient_id == current_user_id, ChatMessage.is_deleted_by_recipient == False)
            )
        ).order_by(desc(ChatMessage.sent_at))
        
        # Paginate results
        messages_paginated = messages_query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        # Convert to dict and decrypt
        messages_list = []
        for message in messages_paginated.items:
            message_dict = message.to_dict()
            
            # Add sender info
            sender = User.query.get(message.sender_id)
            if sender:
                message_dict['sender_info'] = {
                    'username': encryptor.decrypt(sender.username),
                    'role': sender.role.name
                }
            
            messages_list.append(message_dict)
        
        # Reverse to show oldest first
        messages_list.reverse()
        
        return jsonify({
            'messages': messages_list,
            'pagination': {
                'page': messages_paginated.page,
                'per_page': messages_paginated.per_page,
                'total': messages_paginated.total,
                'pages': messages_paginated.pages,
                'has_next': messages_paginated.has_next,
                'has_prev': messages_paginated.has_prev
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get chat history: {str(e)}'}), 500

def get_conversations():
    """Get list of all conversations for the current user."""
    try:
        current_user_id = int(get_jwt_identity())
        
        # Get all chat rooms where user is involved
        rooms = ChatRoom.query.filter(
            or_(ChatRoom.user1_id == current_user_id, ChatRoom.user2_id == current_user_id)
        ).order_by(desc(ChatRoom.last_message_at)).all()
        
        conversations = []
        for room in rooms:
            other_user_id = room.get_other_user_id(current_user_id)
            other_user = User.query.get(other_user_id)
            
            if not other_user:
                continue
            
            # Get last message in this conversation
            last_message = ChatMessage.query.filter(
                or_(
                    and_(ChatMessage.sender_id == current_user_id, ChatMessage.recipient_id == other_user_id),
                    and_(ChatMessage.sender_id == other_user_id, ChatMessage.recipient_id == current_user_id)
                )
            ).order_by(desc(ChatMessage.sent_at)).first()
            
            # Get unread count
            unread_count = ChatMessage.query.filter(
                ChatMessage.sender_id == other_user_id,
                ChatMessage.recipient_id == current_user_id,
                ChatMessage.is_read == False,
                ChatMessage.is_deleted_by_recipient == False
            ).count()
            
            # Decrypt other user's info
            try:
                other_user_username = encryptor.decrypt(other_user.username)
            except:
                other_user_username = "[Decryption Error]"
            
            conversation_data = {
                'room_id': room.id,
                'other_user_id': other_user_id,
                'other_user_username': other_user_username,
                'other_user_role': other_user.role.name,
                'is_online': is_user_online(other_user_id),
                'unread_count': unread_count,
                'last_message_at': room.last_message_at.isoformat(),
                'last_message': None
            }
            
            if last_message:
                conversation_data['last_message'] = {
                    'content': encryptor.decrypt(last_message.message_content),
                    'sender_id': last_message.sender_id,
                    'sent_at': last_message.sent_at.isoformat()
                }
            
            conversations.append(conversation_data)
        
        return jsonify({'conversations': conversations}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get conversations: {str(e)}'}), 500

def delete_message(message_id):
    """Delete a message (soft delete)."""
    try:
        current_user_id = int(get_jwt_identity())
        message = ChatMessage.query.get(message_id)
        
        if not message:
            return jsonify({'error': 'Message not found'}), 404
        
        # Check if user is sender or recipient
        if message.sender_id == current_user_id:
            message.is_deleted_by_sender = True
        elif message.recipient_id == current_user_id:
            message.is_deleted_by_recipient = True
        else:
            return jsonify({'error': 'You can only delete your own messages'}), 403
        
        db.session.commit()
        
        return jsonify({'message': 'Message deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete message: {str(e)}'}), 500

def get_chateable_users():
    """Get list of users that the current user can chat with."""
    try:
        current_user_id = int(get_jwt_identity())
        current_user = User.query.get(current_user_id)
        
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        
        chateable_users = []
        
        if current_user.role.name == 'doctor':
            # Doctors can chat with their assigned patients
            patients = current_user.assigned_patients.filter(User.is_active == True).all()
            for patient in patients:
                try:
                    username = encryptor.decrypt(patient.username)
                    first_name = ""
                    last_name = ""
                    
                    if patient.patient_profile:
                        first_name = encryptor.decrypt(patient.patient_profile.first_name) or ""
                        last_name = encryptor.decrypt(patient.patient_profile.last_name) or ""
                    
                    chateable_users.append({
                        'id': patient.id,
                        'username': username,
                        'role': patient.role.name,
                        'full_name': f"{first_name} {last_name}".strip(),
                        'is_online': is_user_online(patient.id)
                    })
                except:
                    continue
                    
        elif current_user.role.name == 'patient':
            # Patients can chat with their assigned doctors
            doctors = current_user.assigned_doctors.filter(User.is_active == True).all()
            for doctor in doctors:
                try:
                    username = encryptor.decrypt(doctor.username)
                    first_name = ""
                    last_name = ""
                    
                    if doctor.doctor_profile:
                        first_name = encryptor.decrypt(doctor.doctor_profile.first_name) or ""
                        last_name = encryptor.decrypt(doctor.doctor_profile.last_name) or ""
                    
                    chateable_users.append({
                        'id': doctor.id,
                        'username': username,
                        'role': doctor.role.name,
                        'full_name': f"{first_name} {last_name}".strip(),
                        'specialization': doctor.doctor_profile.specialization,
                        'is_online': is_user_online(doctor.id)
                    })
                except:
                    continue
                    
        elif current_user.role.name in ['admin', 'superadmin']:
            # Admins can chat with all active users except themselves
            users = User.query.filter(
                User.is_active == True,
                User.id != current_user_id
            ).all()
            
            for user in users:
                try:
                    username = encryptor.decrypt(user.username)
                    first_name = ""
                    last_name = ""
                    
                    if user.doctor_profile:
                        first_name = encryptor.decrypt(user.doctor_profile.first_name) or ""
                        last_name = encryptor.decrypt(user.doctor_profile.last_name) or ""
                    elif user.patient_profile:
                        first_name = encryptor.decrypt(user.patient_profile.first_name) or ""
                        last_name = encryptor.decrypt(user.patient_profile.last_name) or ""
                    
                    chateable_users.append({
                        'id': user.id,
                        'username': username,
                        'role': user.role.name,
                        'full_name': f"{first_name} {last_name}".strip(),
                        'is_online': is_user_online(user.id)
                    })
                except:
                    continue
        
        return jsonify({'users': chateable_users}), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get chateable users: {str(e)}'}), 500

def mark_messages_read():
    """Mark messages as read via REST API."""
    try:
        current_user_id = int(get_jwt_identity())
        data = request.get_json()
        
        message_ids = data.get('message_ids', [])
        other_user_id = data.get('other_user_id')
        
        if message_ids:
            # Mark specific messages as read
            messages = ChatMessage.query.filter(
                ChatMessage.id.in_(message_ids),
                ChatMessage.recipient_id == current_user_id,
                ChatMessage.is_read == False
            ).all()
        elif other_user_id:
            # Mark all messages from a specific user as read
            messages = ChatMessage.query.filter(
                ChatMessage.sender_id == other_user_id,
                ChatMessage.recipient_id == current_user_id,
                ChatMessage.is_read == False
            ).all()
        else:
            return jsonify({'error': 'Either message_ids or other_user_id is required'}), 400
        
        for message in messages:
            message.is_read = True
            message.read_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'message': 'Messages marked as read',
            'count': len(messages)
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to mark messages as read: {str(e)}'}), 500