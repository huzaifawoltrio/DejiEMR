# /run.py
from dotenv import load_dotenv

# Load environment variables from .env file FIRST.
# This must happen before any other app imports.
load_dotenv()

# Now, import the app factory
from app import create_app
from app.extensions import socketio

# Create the app instance (it will now have the correct config)
app = create_app()

if __name__ == '__main__':
    # Use SocketIO's run method instead of app.run() for WebSocket support
    socketio.run(app, debug=True, host='127.0.0.1', port=5000)