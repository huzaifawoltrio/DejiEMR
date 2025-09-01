# /run.py
# IMPORTANT: If using eventlet, monkey patch MUST be the very first thing
import eventlet
eventlet.monkey_patch()

# Load environment variables from .env file AFTER monkey patching
from dotenv import load_dotenv
load_dotenv()

# Now, import the app factory
from app import create_app

# Create the app instance (it will now have the correct config)
app = create_app()

if __name__ == '__main__':
    # Use eventlet's wsgi server instead of Flask's development server
    import eventlet.wsgi
    eventlet.wsgi.server(eventlet.listen(('127.0.0.1', 5000)), app)