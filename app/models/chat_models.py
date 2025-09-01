# /app/models/chat_models.py
from datetime import datetime
from app.extensions import db
from app.utils.encryption_util import encryptor

class ChatMessage(db.Model):
    """Model for storing encrypted chat messages between users."""
    __tablename__ = 'chat_messages'

    id = db.Column(db.Integer, primary_key=True)
    
    # User relationships
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Encrypted message content
    message_content = db.Column(db.Text, nullable=False)  # Encrypted
    
    # Message metadata
    message_type = db.Column(db.String(50), default='text')  # 'text', 'file', 'image', etc.
    is_read = db.Column(db.Boolean, default=False)
    is_deleted_by_sender = db.Column(db.Boolean, default=False)
    is_deleted_by_recipient = db.Column(db.Boolean, default=False)
    
    # Timestamps
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    read_at = db.Column(db.DateTime)
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')
    
    def to_dict(self, decrypt_content=True):
        """Convert message to dictionary format for API responses."""
        data = {
            'id': self.id,
            'sender_id': self.sender_id,
            'recipient_id': self.recipient_id,
            'message_type': self.message_type,
            'is_read': self.is_read,
            'sent_at': self.sent_at.isoformat() if self.sent_at else None,
            'read_at': self.read_at.isoformat() if self.read_at else None,
        }
        
        if decrypt_content:
            try:
                data['content'] = encryptor.decrypt(self.message_content)
            except Exception:
                data['content'] = '[Decryption Error]'
        else:
            data['content'] = '[Encrypted]'
            
        return data

class ChatRoom(db.Model):
    """Model for chat rooms/conversations between users."""
    __tablename__ = 'chat_rooms'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Participants (for now, supporting 1-on-1 chats)
    user1_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Room metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_message_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])
    
    # Ensure unique pairs (regardless of order)
    __table_args__ = (
        db.CheckConstraint('user1_id != user2_id', name='different_users'),
        db.UniqueConstraint('user1_id', 'user2_id', name='unique_chat_pair'),
    )
    
    @classmethod
    def get_or_create_room(cls, user1_id, user2_id):
        """Get existing room or create new one between two users."""
        # Ensure consistent ordering to avoid duplicates
        if user1_id > user2_id:
            user1_id, user2_id = user2_id, user1_id
            
        room = cls.query.filter_by(user1_id=user1_id, user2_id=user2_id).first()
        
        if not room:
            room = cls(user1_id=user1_id, user2_id=user2_id)
            db.session.add(room)
            db.session.commit()
            
        return room
    
    def get_other_user_id(self, current_user_id):
        """Get the ID of the other user in the chat room."""
        return self.user2_id if self.user1_id == current_user_id else self.user1_id
    
    def to_dict(self):
        """Convert room to dictionary format."""
        return {
            'id': self.id,
            'user1_id': self.user1_id,
            'user2_id': self.user2_id,
            'created_at': self.created_at.isoformat(),
            'last_message_at': self.last_message_at.isoformat()
        }