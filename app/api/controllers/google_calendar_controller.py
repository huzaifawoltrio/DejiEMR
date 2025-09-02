from flask import redirect, url_for, session, request, jsonify
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from app.models.google_meet_model import GoogleMeetLink
import os


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
    """Starts the OAuth 2.0 authorization flow."""
    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=url_for('api.oauth2callback', _external=True)
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

def oauth2callback():
    """Callback route for the OAuth 2.0 flow."""
    state = session['state']
    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for('api.oauth2callback', _external=True)
    )
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    
    credentials = flow.credentials
    # Store credentials in session
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    return redirect(url_for('api.create_event')) # Make sure to use the correct endpoint name

def create_google_meet_event():
    """Creates a Google Calendar event from POST data and saves it."""
    creds_dict = session.get('credentials')
    if not creds_dict:
        return redirect(url_for('api.authorize'))

    # 1. Get meeting data from the request body
    data = request.get_json()
    if not data or not all(k in data for k in ['summary', 'start_time', 'end_time', 'attendees']):
        return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400

    summary = data['summary']
    start_time_iso = data['start_time'] # Expecting ISO 8601 format: "2025-09-10T09:00:00"
    end_time_iso = data['end_time']
    attendees_emails = data['attendees'] # Expecting a list of emails: ["doc@example.com", "patient@example.com"]
    description = data.get('description', '')

    # 2. Build the Google Calendar service
    credentials = Credentials(**creds_dict)
    service = build('calendar', 'v3', credentials=credentials)

    # 3. Construct the event payload
    event = {
        'summary': summary,
        'description': description,
        'start': {'dateTime': start_time_iso, 'timeZone': 'UTC'},
        'end': {'dateTime': end_time_iso, 'timeZone': 'UTC'},
        'conferenceData': {
            'createRequest': {
                'requestId': f'dejiemr-meeting-{datetime.utcnow().timestamp()}',
                'conferenceSolutionKey': {'type': 'hangoutsMeet'}
            }
        },
        'attendees': [{'email': email} for email in attendees_emails],
    }

    created_event = service.events().insert(
        calendarId='primary', body=event, conferenceDataVersion=1
    ).execute()

    # 4. Create and save the new Meeting record to the database
    new_meeting = Meeting(
        summary=summary,
        description=description,
        start_time=datetime.fromisoformat(start_time_iso),
        end_time=datetime.fromisoformat(end_time_iso),
        attendees=attendees_emails,
        meet_link=created_event.get('hangoutLink'),
        event_id=created_event.get('id')
    )
    db.session.add(new_meeting)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': 'Meeting created and saved successfully.',
        'meeting_id': new_meeting.id,
        'meet_link': new_meeting.meet_link,
        'event_link': created_event.get('htmlLink')
    }), 201
    """Creates a Google Calendar event and persists the link to the database."""
    creds_dict = session.get('credentials')
    if not creds_dict:
        return redirect(url_for('api.authorize'))

    credentials = Credentials(**creds_dict)
    service = build('calendar', 'v3', credentials=credentials)

    # 1. Fetch the appointment from the database
    appointment = Appointment.query.get(appointment_id)
    if not appointment:
        return jsonify({'status': 'error', 'message': 'Appointment not found'}), 404

    # 2. Construct the event using appointment data
    start_time = appointment.appointment_datetime
    end_time = start_time + timedelta(minutes=appointment.duration)
    
    event = {
        'summary': f'Appointment: Dr. {appointment.doctor.username} & {appointment.patient.username}',
        'description': f'Services: {", ".join(appointment.services)}',
        'start': {
            'dateTime': start_time.isoformat(),
            'timeZone': 'UTC',
        },
        'end': {
            'dateTime': end_time.isoformat(),
            'timeZone': 'UTC',
        },
        'conferenceData': {
            'createRequest': {
                'requestId': f'dejiemr-{appointment.id}-{datetime.utcnow().timestamp()}',
                'conferenceSolutionKey': {'type': 'hangoutsMeet'}
            }
        },
        'attendees': [
            {'email': appointment.doctor.email},
            {'email': appointment.patient.email},
        ],
    }

    created_event = service.events().insert(
        calendarId='primary', body=event, conferenceDataVersion=1
    ).execute()

    # 3. Create and save the GoogleMeetLink to the database
    new_meet_link = GoogleMeetLink(
        appointment_id=appointment.id,
        meet_link=created_event.get('hangoutLink'),
        event_id=created_event.get('id')
    )
    db.session.add(new_meet_link)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'message': 'Google Meet link created and saved.',
        'event_link': created_event.get('htmlLink'),
        'meet_link': created_event.get('hangoutLink')
    })
    """Creates a Google Calendar event with a Google Meet link."""
    creds_dict = session.get('credentials')
    if not creds_dict:
        return redirect(url_for('api.authorize'))

    # Recreate the Credentials object from the dictionary in the session
    credentials = Credentials(**creds_dict)

    service = build('calendar', 'v3', credentials=credentials)

    event = {
      'summary': 'Doctor-Client Meeting',
      'description': 'A virtual meeting between a doctor and a client.',
      'start': {
        'dateTime': '2025-09-10T09:00:00-07:00',
        'timeZone': 'America/Los_Angeles',
      },
      'end': {
        'dateTime': '2025-09-10T10:00:00-07:00',
        'timeZone': 'America/Los_Angeles',
      },
      'conferenceData': {
        'createRequest': {
          'requestId': 'some-random-string-1234',
          'conferenceSolutionKey': {
            'type': 'hangoutsMeet'
          }
        }
      },
      # Add attendees (replace with actual doctor and client emails)
      'attendees': [
        {'email': 'doctor@example.com'},
        {'email': 'client@example.com'},
      ],
    }

    created_event = service.events().insert(calendarId='primary', body=event, conferenceDataVersion=1).execute()
    
    # Here you would save the eventId, meet_link, etc. to your database
    # event_id = created_event.get('id')
    # meet_link = created_event.get('hangoutLink')
    
    return jsonify({
        'status': 'success',
        'event_link': created_event.get('htmlLink'), 
        'meet_link': created_event.get('hangoutLink')
    })


def reschedule_event(event_id, new_start_time, new_end_time):
    """Reschedules a Google Calendar event."""
    credentials = session.get('credentials')
    if not credentials:
        return redirect(url_for('authorize'))

    service = build('calendar', 'v3', credentials=credentials)

    # First, retrieve the event from the API.
    event = service.events().get(calendarId='primary', eventId=event_id).execute()

    event['start']['dateTime'] = new_start_time
    event['end']['dateTime'] = new_end_time

    updated_event = service.events().update(
        calendarId='primary', eventId=event['id'], body=event).execute()
    return jsonify({'updated_event_link': updated_event.get('htmlLink')})

def cancel_event(event_id):
    """Cancels a Google Calendar event."""
    credentials = session.get('credentials')
    if not credentials:
        return redirect(url_for('authorize'))

    service = build('calendar', 'v3', credentials=credentials)
    service.events().delete(calendarId='primary', eventId=event_id).execute()
    return jsonify({'message': 'Event canceled successfully.'})