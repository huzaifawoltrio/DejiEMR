# /app/socket_handlers/chat_handler.py
from flask import request
from flask_socketio import emit, join_room, leave_room, disconnect
from flask_jwt_extended import decode_token, get_jwt_identity
from app.extensions import db, socketio
from app.models.user_models import User
from app.models.chat_models import ChatMessage, ChatRoom
from app.utils.encryption_util import encryptor
from datetime import datetime
import logging

# Store active connections: {user_id: {session_id: socket_id}}
active_connections = {}

def get_user_from_token():
    """Extract user from JWT token in socket request."""
    try:
        token = request.args.get('token')
        if not token:
            return None
            
        decoded_token = decode_token(token)
        user_id = decoded_token['sub']
        return User.query.get(user_id)
    except Exception as e:
        logging.error(f"Token validation error: {e}")
        return None

def can_users_chat(user1, user2):
    """Check if two users are allowed to chat based on business rules."""
    if not user1 or not user2:
        return False
        
    # Same user cannot chat with themselves
    if user1.id == user2.id:
        return False
        
    role1, role2 = user1.role.name, user2.role.name
    
    # Admin and superadmin can chat with anyone
    if role1 in ['admin', 'superadmin'] or role2 in ['admin', 'superadmin']:
        return True
    
    # Doctor-Patient relationship check
    if role1 == 'doctor' and role2 == 'patient':
        return user1.assigned_patients.filter_by(id=user2.id).first() is not None
    elif role1 == 'patient' and role2 == 'doctor':
        return user2.assigned_patients.filter_by(id=user1.id).first() is not None
    
    # For now, restrict other combinations
    return False

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    user = get_user_from_token()
    if not user:
        emit('error', {'message': 'Authentication required'})
        disconnect()
        return
    
    session_id = request.sid
    
    # Store connection
    if user.id not in active_connections:
        active_connections[user.id] = {}
    active_connections[user.id][session_id] = True
    
    # Join personal room for receiving messages
    join_room(f"user_{user.id}")
    
    emit('connected', {
        'message': 'Connected successfully',
        'user_id': user.id
    })
    
    logging.info(f"User {user.id} connected with session {session_id}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    user = get_user_from_token()
    if user:
        session_id = request.sid
        
        # Remove connection
        if user.id in active_connections and session_id in active_connections[user.id]:
            del active_connections[user.id][session_id]
            
            # Clean up empty user entries
            if not active_connections[user.id]:
                del active_connections[user.id]
        
        leave_room(f"user_{user.id}")
        logging.info(f"User {user.id} disconnected from session {session_id}")

@socketio.on('send_message')
def handle_send_message(data):
    """Handle sending a message."""
    try:
        user = get_user_from_token()
        if not user:
            emit('error', {'message': 'Authentication required'})
            return
        
        recipient_id = data.get('recipient_id')
        content = data.get('content')
        message_type = data.get('message_type', 'text')
        
        if not recipient_id or not content:
            emit('error', {'message': 'Recipient ID and content are required'})
            return
        
        recipient = User.query.get(recipient_id)
        if not recipient:
            emit('error', {'message': 'Recipient not found'})
            return
        
        # Check if users can chat
        if not can_users_chat(user, recipient):
            emit('error', {'message': 'You are not authorized to chat with this user'})
            return
        
        # Create or get chat room
        room = ChatRoom.get_or_create_room(user.id, recipient_id)
        
        # Create encrypted message
        encrypted_content = encryptor.encrypt(content)
        message = ChatMessage(
            sender_id=user.id,
            recipient_id=recipient_id,
            message_content=encrypted_content,
            message_type=message_type
        )
        
        db.session.add(message)
        
        # Update room's last message timestamp
        room.last_message_at = datetime.utcnow()
        db.session.commit()
        
        # Prepare message data for emission
        message_data = {
            'id': message.id,
            'sender_id': user.id,
            'recipient_id': recipient_id,
            'content': content,  # Send unencrypted to clients
            'message_type': message_type,
            'sent_at': message.sent_at.isoformat(),
            'sender_info': {
                'username': encryptor.decrypt(user.username),
                'role': user.role.name
            }
        }
        
        # Emit to sender (confirmation)
        emit('message_sent', message_data)
        
        # Emit to recipient if online
        socketio.emit('new_message', message_data, room=f"user_{recipient_id}")
        
        logging.info(f"Message sent from user {user.id} to user {recipient_id}")
        
    except Exception as e:
        logging.error(f"Error sending message: {e}")
        emit('error', {'message': 'Failed to send message'})

@socketio.on('mark_as_read')
def handle_mark_as_read(data):
    """Mark messages as read."""
    try:
        user = get_user_from_token()
        if not user:
            emit('error', {'message': 'Authentication required'})
            return
        
        message_ids = data.get('message_ids', [])
        
        # Update messages to mark as read
        messages = ChatMessage.query.filter(
            ChatMessage.id.in_(message_ids),
            ChatMessage.recipient_id == user.id,
            ChatMessage.is_read == False
        ).all()
        
        for message in messages:
            message.is_read = True
            message.read_at = datetime.utcnow()
        
        db.session.commit()
        
        # Notify sender about read status
        for message in messages:
            socketio.emit('message_read', {
                'message_id': message.id,
                'read_at': message.read_at.isoformat(),
                'reader_id': user.id
            }, room=f"user_{message.sender_id}")
        
        emit('messages_marked_read', {'count': len(messages)})
        
    except Exception as e:
        logging.error(f"Error marking messages as read: {e}")
        emit('error', {'message': 'Failed to mark messages as read'})

@socketio.on('get_online_status')
def handle_get_online_status(data):
    """Check if a user is online."""
    try:
        user_ids = data.get('user_ids', [])
        online_status = {}
        
        for user_id in user_ids:
            online_status[str(user_id)] = user_id in active_connections
            
        emit('online_status', online_status)
        
    except Exception as e:
        logging.error(f"Error getting online status: {e}")
        emit('error', {'message': 'Failed to get online status'})

def is_user_online(user_id):
    """Check if a specific user is online."""
    return user_id in active_connections and len(active_connections[user_id]) > 0