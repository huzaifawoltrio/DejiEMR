# /app/api/controllers/google_calendar_controller.py
from flask import redirect, url_for, session, request, jsonify
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


SCOPES = ['https://www.googleapis.com/auth/calendar']

# Client configuration from environment variables
client_config = {
    "web": {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
}

def authorize():
    """Starts the OAuth 2.0 authorization flow. Now PUBLIC but with security measures."""
    try:
        # Check if this is an authenticated user making the request
        user_id = None
        try:
            # Try to get user ID if JWT is present (but don't require it)
            verify_jwt_in_request(optional=True)
            user_id = get_jwt_identity()
        except:
            # If no JWT or invalid JWT, that's OK for OAuth initiation
            pass
        
        # Get the frontend URL from environment or default
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        
        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=url_for('api.oauth2callback', _external=True)
        )
        
        # Generate a secure state parameter that includes user info (if available)
        state_data = {
            'csrf_token': secrets.token_urlsafe(32),
            'user_id': user_id,
            'timestamp': int(datetime.utcnow().timestamp())
        }
        
        # Create a simple state string (in production, consider encrypting this)
        import json
        import base64
        state = base64.urlsafe_b64encode(
            json.dumps(state_data).encode()
        ).decode()
        
        authorization_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            state=state  # Use our custom state
        )
        
        # Store state in session for security verification
        session['oauth_state'] = state
        session['oauth_user_id'] = user_id  # Store user ID for callback
        
        # Check if this is an AJAX request or direct browser request
        if request.headers.get('Content-Type') == 'application/json' or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # Return JSON response for AJAX requests
            return jsonify({
                'authorization_url': authorization_url,
                'state': state
            }), 200
        else:
            # Direct redirect for browser requests
            return redirect(authorization_url)
        
    except Exception as e:
        if request.headers.get('Content-Type') == 'application/json':
            return jsonify({'error': f'Failed to initiate authorization: {str(e)}'}), 500
        else:
            frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
            return redirect(f"{frontend_url}/telemedicine?google_auth=error&message={str(e)}")

def oauth2callback():
    """Callback route for the OAuth 2.0 flow. PUBLIC endpoint."""
    try:
        # Verify state parameter for CSRF protection
        returned_state = request.args.get('state')
        session_state = session.get('oauth_state')
        
        if not returned_state or returned_state != session_state:
            raise Exception('Invalid state parameter - possible CSRF attack')
            
        # Decode and verify state data
        import json
        import base64
        try:
            state_data = json.loads(
                base64.urlsafe_b64decode(returned_state.encode()).decode()
            )
            
            # Check if state is not too old (5 minutes max)
            state_age = datetime.utcnow().timestamp() - state_data.get('timestamp', 0)
            if state_age > 300:  # 5 minutes
                raise Exception('OAuth state expired')
                
        except:
            raise Exception('Invalid state format')
            
        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            state=returned_state,
            redirect_uri=url_for('api.oauth2callback', _external=True)
        )
        
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)
        
        credentials = flow.credentials
        user_id = session.get('oauth_user_id') or state_data.get('user_id')
        
        # If no user_id available, we can still store credentials in session
        # but we should warn that they need to be logged in to use the integration
        
        # Store credentials in session (consider using database for production)
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }
        
        # Get user info from Google
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        
        session['google_user_info'] = {
            'id': user_info.get('id'),
            'name': user_info.get('name'),
            'email': user_info.get('email'),
            'picture': user_info.get('picture'),
        }
        
        # Clear OAuth session data
        session.pop('oauth_state', None)
        session.pop('oauth_user_id', None)
        
        # Redirect to frontend with success
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        if user_id:
            return redirect(f"{frontend_url}/telemedicine?google_auth=success")
        else:
            # User was not logged in during OAuth - they'll need to log in to use features
            return redirect(f"{frontend_url}/telemedicine?google_auth=success&warning=please_login")
        
    except Exception as e:
        # Clear any OAuth session data
        session.pop('oauth_state', None)
        session.pop('oauth_user_id', None)
        
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        return redirect(f"{frontend_url}/telemedicine?google_auth=error&message={str(e)}")

@jwt_required()
def check_google_connection():
    """Check if user has Google Calendar connected."""
    try:
        creds_dict = session.get('credentials')
        user_info = session.get('google_user_info')
        
        if creds_dict and user_info:
            # Verify credentials are still valid
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
    start_time_iso = data['start_time']  # Expecting ISO 8601 format: "2025-09-10T09:00:00"
    end_time_iso = data['end_time']
    attendees_emails = data['attendees']  # Expecting a list of emails
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
                {'method': 'email', 'minutes': 24 * 60},  # 24 hours before
                {'method': 'popup', 'minutes': 10},       # 10 minutes before
            ],
        },
    }

    try:
        created_event = service.events().insert(
            calendarId='primary', 
            body=event, 
            conferenceDataVersion=1,
            sendNotifications=True  # Send email notifications to attendees
        ).execute()

        # 4. Create and save the new Meeting record to the database
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
        return jsonify({
            'status': 'error',
            'message': f'Failed to create Google Meet event: {str(e)}'
        }), 500

@jwt_required()
def get_meetings():
    """Get all meetings for the current user."""
    try:
        # Get meetings from database
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

        # First, retrieve the event from the API.
        event = service.events().get(calendarId='primary', eventId=event_id).execute()

        # Update the event times
        event['start']['dateTime'] = new_start_time
        event['end']['dateTime'] = new_end_time

        updated_event = service.events().update(
            calendarId='primary', 
            eventId=event['id'], 
            body=event,
            sendNotifications=True  # Notify attendees of the change
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
        
        # Delete the event from Google Calendar
        service.events().delete(
            calendarId='primary', 
            eventId=event_id,
            sendNotifications=True  # Notify attendees of cancellation
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