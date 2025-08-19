# /app/utils/error_handlers.py
from flask import jsonify, current_app
from app.extensions import db

def register_error_handlers(app):
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Resource not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        current_app.audit_logger.error(f"Internal server error: {str(error)}")
        return jsonify({'error': 'Internal server error'}), 500