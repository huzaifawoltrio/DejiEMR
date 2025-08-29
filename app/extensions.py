# huzaifawoltrio/dejiemr/DejiEMR-new-patient-profile/app/extensions.py
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO

db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
cors = CORS()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)
socketio = SocketIO(cors_allowed_origins="*")
