# /run.py

import os
from app import create_app
from app.extensions import db, migrate # 1. Import the 'migrate' instance

# Create the application instance
app = create_app()

# 2. Initialize Flask-Migrate with the app and db.
# This must be done after the app and db instances are created.
migrate.init_app(app, db)

if __name__ == '__main__':
    # Running with debug mode and SSL context
    app.run(debug=True, ssl_context='adhoc')
