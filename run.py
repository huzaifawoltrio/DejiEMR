# /run.py
"""
Fixed version that handles eventlet monkey patching properly
and avoids conflicts with Flask CLI commands.
"""
import os
import sys

# Only apply eventlet monkey patching when running the server, not CLI commands
if 'flask' not in sys.argv[0] and 'db' not in sys.argv:
    import eventlet
    eventlet.monkey_patch()

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Now, import the app factory
from app import create_app

# Create the app instance
app = create_app()

if __name__ == '__main__':
    # Check if we're running with eventlet
    if 'eventlet' in sys.modules:
        # Use eventlet's wsgi server for production-like async support
        import eventlet.wsgi
        print("Starting server with eventlet...")
        eventlet.wsgi.server(eventlet.listen(('127.0.0.1', 5000)), app)
    else:
        # Use Flask's development server for CLI commands and simple testing
        print("Starting server with Flask dev server...")
        app.run(host='127.0.0.1', port=5000, debug=True)