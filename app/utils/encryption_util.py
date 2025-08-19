# /app/utils/encryption_util.py
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

class Encryptor:
    """
    A utility class for encrypting and decrypting data.
    It must be initialized with the Flask app context to load the key.
    """
    def __init__(self, app=None):
        self.fernet = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initializes the Fernet suite with the key from the app's config."""
        key = app.config.get('EMR_ENCRYPTION_KEY')
        if not key:
            raise ValueError("EMR_ENCRYPTION_KEY not set in the Flask application config.")
        
        self.fernet = Fernet(key.encode())

    def encrypt(self, data: str) -> str:
        """Encrypts a string."""
        if self.fernet is None:
            raise RuntimeError("Encryptor has not been initialized with an app context.")
        
        if not isinstance(data, str):
            data = str(data)
            
        encrypted_data = self.fernet.encrypt(data.encode('utf-8'))
        return encrypted_data.decode('utf-8')

    def decrypt(self, token: str) -> str | None:
        """Decrypts an encrypted token string."""
        if self.fernet is None:
            raise RuntimeError("Encryptor has not been initialized with an app context.")

        if not token:
            return None
            
        try:
            decrypted_data = self.fernet.decrypt(token.encode('utf-8'))
            return decrypted_data.decode('utf-8')
        except InvalidToken:
            current_app.logger.error("Decryption failed: Invalid token provided.")
            return None
        except Exception as e:
            current_app.logger.error(f"An unexpected error occurred during decryption: {e}")
            return None

# Create a single, uninitialized instance to be imported by other modules.
encryptor = Encryptor()
