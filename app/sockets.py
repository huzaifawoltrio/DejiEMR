# huzaifawoltrio/dejiemr/DejiEMR-new-patient-profile/app/sockets.py
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_jwt_extended import decode_token
from app.extensions import db
from app.models.user_models import User
from app.models.chat_models import ChatMessage
from app.utils.encryption_util import encryptor

socketio = SocketIO()

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('join')
def on_join(data):
    token = data.get('token')
    if not token:
        return
    try:
        decoded_token = decode_token(token)
        user_id = decoded_token['sub']
        join_room(user_id)
        print(f"User {user_id} joined room")
    except Exception as e:
        print(f"Error joining room: {e}")


@socketio.on('private_message')
def handle_private_message(data):
    token = data.get('token')
    if not token:
        return

    try:
        decoded_token = decode_token(token)
        sender_id = decoded_token['sub']
        
        recipient_id = data['recipient_id']
        message_text = data['message']

        encrypted_message = encryptor.encrypt(message_text)

        new_message = ChatMessage(
            sender_id=sender_id,
            receiver_id=recipient_id,
            message=encrypted_message
        )
        db.session.add(new_message)
        db.session.commit()

        emit('new_message', new_message.to_dict(), room=recipient_id)
        emit('new_message', new_message.to_dict(), room=sender_id)

    except Exception as e:
        print(f"Error sending message: {e}")
