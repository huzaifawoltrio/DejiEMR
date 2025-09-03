# /app/api/controllers/google_calendar_controller.py
from flask import redirect, url_for, session, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from datetime import datetime, timedelta
from app.models.google_meet_model import Meeting
from app.models.user_models import User
from app.extensions import db
import os
import secrets
import json
import base64
from urllib.parse import urlencode


SCOPES = ['https://www.googleapis.com/auth/calendar']

# Client configuration from environment variables
def get_client_config():
    """Get client config with proper redirect URI."""
    return {
        "web": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [url_for('api.oauth2callback', _external=True)]
        }
    }

def authorize():
    """Starts the OAuth 2.0 authorization flow. Now PUBLIC but with security measures."""
    try:
        # Check if this is an authenticated user making the request
        user_id = None
        try:
            verify_jwt_in_request(optional=True)
            user_id = get_jwt_identity()
        except:
            pass
        
        # Get the frontend URL from environment or default
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        
        # Build redirect URI - must be absolute and consistent
        redirect_uri = url_for('api.oauth2callback', _external=True, _scheme='http')
        
        # Create flow with explicit redirect URI
        flow = Flow.from_client_config(
            get_client_config(),
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        
        # Generate a simple, secure state token
        state = secrets.token_urlsafe(32)
        
        authorization_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            state=state,
            prompt='consent'  # Force consent to ensure refresh token
        )
        
        # Store state and user info in session
        session['oauth_state'] = state
        session['oauth_user_id'] = user_id
        session.permanent = True  # Make session permanent
        session.modified = True  # Force session save
        
        # Log for debugging
        current_app.logger.info(f"OAuth authorize - State: {state[:10]}..., User: {user_id}")
        
        # Check if this is an AJAX request
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'authorization_url': authorization_url,
                'state': state
            }), 200
        else:
            # Direct redirect for browser requests
            return redirect(authorization_url)
        
    except Exception as e:
        current_app.logger.error(f"OAuth authorize error: {str(e)}")
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'error': f'Failed to initiate authorization: {str(e)}'}), 500
        else:
            frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
            error_msg = str(e).replace(' ', '%20')
            return redirect(f"{frontend_url}/telemedicine?google_auth=error&message={error_msg}")

def oauth2callback():
    """Callback route for the OAuth 2.0 flow. PUBLIC endpoint."""
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
    
    try:
        # Check for error from Google
        error = request.args.get('error')
        if error:
            raise Exception(f"Google OAuth error: {error}")
        
        # Get state parameters
        returned_state = request.args.get('state')
        session_state = session.get('oauth_state')
        
        # Log for debugging
        current_app.logger.info(f"OAuth callback - Returned state: {returned_state[:10] if returned_state else 'None'}...")
        current_app.logger.info(f"OAuth callback - Session state: {session_state[:10] if session_state else 'None'}...")
        
        # For development/testing: Allow bypassing state check if both are None
        if os.getenv('FLASK_ENV') == 'development':
            if not returned_state and not session_state:
                current_app.logger.warning("Development mode: Bypassing state check (both None)")
                # Continue without state validation in dev mode
            elif returned_state != session_state:
                raise Exception(f'State mismatch - Session has different state than returned')
        else:
            # Production: Strict state checking
            if not returned_state or not session_state or returned_state != session_state:
                raise Exception('Invalid state parameter - possible CSRF attack')
        
        # Build redirect URI - must match exactly what was used in authorize()
        redirect_uri = url_for('api.oauth2callback', _external=True, _scheme='http')
        
        # Create flow with same configuration
        flow = Flow.from_client_config(
            get_client_config(),
            scopes=SCOPES,
            state=returned_state,
            redirect_uri=redirect_uri
        )
        
        # Get the authorization response (current URL)
        authorization_response = request.url
        # If using HTTPS but Flask thinks it's HTTP, fix the scheme
        if 'https' in request.headers.get('X-Forwarded-Proto', ''):
            authorization_response = authorization_response.replace('http://', 'https://')
        
        flow.fetch_token(authorization_response=authorization_response)
        
        credentials = flow.credentials
        user_id = session.get('oauth_user_id')
        
        # Store credentials in session
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        
        # Get user info from Google
        try:
            service = build('oauth2', 'v2', credentials=credentials)
            user_info = service.userinfo().get().execute()
            
            session['google_user_info'] = {
                'id': user_info.get('id'),
                'name': user_info.get('name'),
                'email': user_info.get('email'),
                'picture': user_info.get('picture'),
            }
        except Exception as e:
            current_app.logger.warning(f"Failed to get Google user info: {str(e)}")
            session['google_user_info'] = {
                'email': 'Connected',
                'name': 'Google User'
            }
        
        # Clear OAuth session data
        session.pop('oauth_state', None)
        session.pop('oauth_user_id', None)
        session.modified = True  # Force session save
        
        # Redirect to frontend with success
        if user_id:
            return redirect(f"{frontend_url}/telemedicine?google_auth=success")
        else:
            return redirect(f"{frontend_url}/telemedicine?google_auth=success&warning=please_login")
        
    except Exception as e:
        current_app.logger.error(f"OAuth callback error: {str(e)}")
        
        # Clear any OAuth session data
        session.pop('oauth_state', None)
        session.pop('oauth_user_id', None)
        session.modified = True
        
        error_msg = str(e).replace(' ', '%20').replace('=', '%3D')
        return redirect(f"{frontend_url}/telemedicine?google_auth=error&message={error_msg}")

@jwt_required()
def check_google_connection():
    """Check if user has Google Calendar connected."""
    try:
        creds_dict = session.get('credentials')
        user_info = session.get('google_user_info')
        
        if creds_dict and user_info:
            # Verify credentials are still valid
            try:
                credentials = Credentials(**creds_dict)
                if credentials.expired and credentials.refresh_token:
                    from google.auth.transport.requests import Request
                    credentials.refresh(Request())
                    # Update session with new credentials
                    session['credentials'] = {
                        'token': credentials.token,
                        'refresh_token': credentials.refresh_token,
                        'token_uri': credentials.token_uri,
                        'client_id': credentials.client_id,
                        'client_secret': credentials.client_secret,
                        'scopes': credentials.scopes
                    }
                    session.modified = True
            except Exception as e:
                current_app.logger.warning(f"Failed to refresh credentials: {str(e)}")
                # Credentials might be invalid, return as disconnected
                return jsonify({'isConnected': False}), 200
            
            return jsonify({
                'isConnected': True,
                'userInfo': user_info
            }), 200
        else:
            return jsonify({
                'isConnected': False
            }), 200
            
    except Exception as e:
        return jsonify({
            'isConnected': False,
            'error': str(e)
        }), 200

@jwt_required()
def disconnect_google():
    """Disconnect Google account."""
    try:
        # Clear session data
        session.pop('credentials', None)
        session.pop('google_user_info', None)
        session.pop('oauth_state', None)
        session.pop('oauth_user_id', None)
        session.modified = True
        
        return jsonify({
            'success': True,
            'message': 'Google account disconnected successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Failed to disconnect: {str(e)}'
        }), 500

@jwt_required()
def create_google_meet_event():
    """Creates a Google Calendar event from POST data and saves it as a Meeting."""
    creds_dict = session.get('credentials')
    if not creds_dict:
        return jsonify({
            'status': 'error',
            'message': 'Google account not connected. Please authorize first.'
        }), 401

    # 1. Get meeting data from the request body
    data = request.get_json()
    if not data or not all(k in data for k in ['summary', 'start_time', 'end_time', 'attendees']):
        return jsonify({
            'status': 'error', 
            'message': 'Missing required fields: summary, start_time, end_time, attendees'
        }), 400

    summary = data['summary']
    start_time_iso = data['start_time']
    end_time_iso = data['end_time']
    attendees_emails = data['attendees']
    description = data.get('description', '')

    # 2. Build the Google Calendar service
    try:
        credentials = Credentials(**creds_dict)
        service = build('calendar', 'v3', credentials=credentials)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to build calendar service: {str(e)}'
        }), 500

    # 3. Construct the event payload
    event = {
        'summary': summary,
        'description': description,
        'start': {'dateTime': start_time_iso, 'timeZone': 'UTC'},
        'end': {'dateTime': end_time_iso, 'timeZone': 'UTC'},
        'conferenceData': {
            'createRequest': {
                'requestId': f'dejiemr-meeting-{int(datetime.utcnow().timestamp())}',
                'conferenceSolutionKey': {'type': 'hangoutsMeet'}
            }
        },
        'attendees': [{'email': email} for email in attendees_emails],
        'reminders': {
            'useDefault': False,
            'overrides': [
                {'method': 'email', 'minutes': 24 * 60},
                {'method': 'popup', 'minutes': 10},
            ],
        },
    }

    try:
        created_event = service.events().insert(
            calendarId='primary', 
            body=event, 
            conferenceDataVersion=1,
            sendNotifications=True
        ).execute()

        # 4. Create and save the new Meeting record
        new_meeting = Meeting(
            summary=summary,
            description=description,
            start_time=datetime.fromisoformat(start_time_iso.replace('Z', '+00:00')),
            end_time=datetime.fromisoformat(end_time_iso.replace('Z', '+00:00')),
            attendees=attendees_emails,
            meet_link=created_event.get('hangoutLink', ''),
            event_id=created_event.get('id')
        )
        
        db.session.add(new_meeting)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Meeting created and saved successfully.',
            'meeting_id': new_meeting.id,
            'meet_link': new_meeting.meet_link,
            'event_link': created_event.get('htmlLink'),
            'event_id': created_event.get('id')
        }), 201
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to create meeting: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Failed to create Google Meet event: {str(e)}'
        }), 500

@jwt_required()
def get_meetings():
    """Get all meetings for the current user."""
    try:
        meetings = Meeting.query.order_by(Meeting.start_time.desc()).all()
        
        meetings_data = []
        for meeting in meetings:
            meetings_data.append({
                'id': meeting.id,
                'summary': meeting.summary,
                'description': meeting.description,
                'start_time': meeting.start_time.isoformat(),
                'end_time': meeting.end_time.isoformat(),
                'attendees': meeting.attendees,
                'meet_link': meeting.meet_link,
                'event_id': meeting.event_id,
                'created_at': meeting.created_at.isoformat(),
                'updated_at': meeting.updated_at.isoformat()
            })
        
        return jsonify(meetings_data), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to fetch meetings: {str(e)}'
        }), 500

@jwt_required()
def reschedule_event(event_id, new_start_time, new_end_time):
    """Reschedules a Google Calendar event."""
    creds_dict = session.get('credentials')
    if not creds_dict:
        return jsonify({
            'error': 'Google account not connected. Please authorize first.'
        }), 401

    try:
        credentials = Credentials(**creds_dict)
        service = build('calendar', 'v3', credentials=credentials)

        event = service.events().get(calendarId='primary', eventId=event_id).execute()
        event['start']['dateTime'] = new_start_time
        event['end']['dateTime'] = new_end_time

        updated_event = service.events().update(
            calendarId='primary', 
            eventId=event['id'], 
            body=event,
            sendNotifications=True
        ).execute()
        
        # Update the database record
        meeting = Meeting.query.filter_by(event_id=event_id).first()
        if meeting:
            meeting.start_time = datetime.fromisoformat(new_start_time.replace('Z', '+00:00'))
            meeting.end_time = datetime.fromisoformat(new_end_time.replace('Z', '+00:00'))
            meeting.updated_at = datetime.utcnow()
            db.session.commit()
        
        return jsonify({
            'updated_event_link': updated_event.get('htmlLink'),
            'meet_link': updated_event.get('hangoutLink'),
            'message': 'Event rescheduled successfully'
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to reschedule event: {str(e)}'
        }), 500

@jwt_required()
def cancel_event(event_id):
    """Cancels a Google Calendar event."""
    creds_dict = session.get('credentials')
    if not creds_dict:
        return jsonify({
            'error': 'Google account not connected. Please authorize first.'
        }), 401

    try:
        credentials = Credentials(**creds_dict)
        service = build('calendar', 'v3', credentials=credentials)
        
        service.events().delete(
            calendarId='primary', 
            eventId=event_id,
            sendNotifications=True
        ).execute()
        
        # Remove from database
        meeting = Meeting.query.filter_by(event_id=event_id).first()
        if meeting:
            db.session.delete(meeting)
            db.session.commit()
        
        return jsonify({
            'message': 'Event canceled successfully.'
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': f'Failed to cancel event: {str(e)}'
        }), 500