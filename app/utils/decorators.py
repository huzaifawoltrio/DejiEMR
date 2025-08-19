from functools import wraps
from flask import request, current_app, jsonify, make_response
from app.models.system_models import AuditLog
from app.extensions import db
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from sqlalchemy.exc import SQLAlchemyError
from app.models.user_models import User

def audit_log(action, resource):
    """Logs user actions for HIPAA compliance."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = None
            resource_id = None
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')

            try:
                # Attempt to get user_id from a valid JWT token
                user_id = get_jwt_identity()
            except RuntimeError:
                # No JWT token present (e.g., for registration or login)
                pass

            # Capture resource_id from request body for specific actions
            if action == "USER_REGISTRATION" and request.is_json:
                data = request.get_json(silent=True)
                if data:
                    # In a registration attempt, we can only identify the resource by email
                    resource_id = data.get('email')
            
            try:
                # Execute the decorated view function.
                # Use make_response to handle both Response objects and tuples.
                raw_response = f(*args, **kwargs)
                response = make_response(raw_response)
                
                success = response.status_code < 400
                details = f"Request successful. Status: {response.status_code}"
                
                # For a successful registration, get the new user_id from the response
                if action == "USER_REGISTRATION" and success and response.is_json:
                    response_data = response.get_json()
                    user_id = response_data.get('user_id')
                    
                log_entry = AuditLog(
                    user_id=user_id,
                    action=action,
                    resource=resource,
                    resource_id=resource_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=success,
                    details=details
                )
                db.session.add(log_entry)
                db.session.commit()
                current_app.audit_logger.info(
                    f"Action='{action}', Resource='{resource}', UserID='{user_id}', Success='{success}', Details='{details}'"
                )
                
                return response

            except Exception as e:
                details = f"An error occurred: {str(e)}"
                log_entry = AuditLog(
                    user_id=user_id,
                    action=action,
                    resource=resource,
                    resource_id=resource_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    details=details
                )
                try:
                    db.session.add(log_entry)
                    db.session.commit()
                except SQLAlchemyError as db_error:
                    current_app.audit_logger.error(f"Failed to log audit entry due to DB error: {db_error}")
                    db.session.rollback()
                
                current_app.audit_logger.error(
                    f"Action='{action}', Resource='{resource}', UserID='{user_id}', Success='False', Details='{details}'"
                )
                
                raise

        return decorated_function
    return decorator

def require_permission(resource, action):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = User.query.get(user_id)

            if not user or not user.is_active:
                return jsonify({'error': 'User not found or inactive'}), 403

            # 🔑 Always allow superadmin
            if user.role.name == "superadmin":
                return f(*args, **kwargs)

            has_permission = any(
                p.resource == resource and p.action == action
                for p in user.role.permissions
            )

            if not has_permission:
                return jsonify({'error': 'Permission denied'}), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator
    """Checks if the authenticated user has permission to perform an action on a resource."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = User.query.get(user_id)

            if not user or not user.is_active:
                return jsonify({'error': 'User not found or inactive'}), 403

            has_permission = any(
                p.resource == resource and p.action == action 
                for p in user.role.permissions
            )

            if not has_permission:
                return jsonify({'error': 'Permission denied'}), 403
            
            return f(*args, **kwargs)

        return decorated_function
    return decorator
