# /app/utils/email_util.py
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app

def send_password_email(recipient_email: str, username: str, password: str):
    """
    Sends an email to a new doctor with their temporary password.

    Args:
        recipient_email (str): The doctor's email address.
        username (str): The doctor's username.
        password (str): The randomly generated temporary password.
    """
    mail_server = os.environ.get('MAIL_SERVER')
    mail_port = int(os.environ.get('MAIL_PORT', 587))
    mail_use_tls = os.environ.get('MAIL_USE_TLS', 'True').lower() in ['true', '1', 't']
    mail_username = os.environ.get('MAIL_USERNAME')
    mail_password = os.environ.get('MAIL_PASSWORD')

    if not all([mail_server, mail_port, mail_username, mail_password]):
        current_app.logger.error("Email server is not configured. Cannot send password email.")
        # In a real application, you might want to raise an exception
        # or have a more robust fallback.
        return

    sender_email = mail_username
    
    message = MIMEMultipart("alternative")
    message["Subject"] = "Your EMR Account Credentials"
    message["From"] = sender_email
    message["To"] = recipient_email

    # Create the plain-text and HTML version of your message
    text = f"""
    Hello Dr. {username},

    An account has been created for you on the EMR system.
    Your username is: {username}
    Your temporary password is: {password}

    Please log in and change your password immediately.
    """
    
    html = f"""
    <html>
      <body>
        <h2>Welcome to the EMR System</h2>
        <p>Hello Dr. {username},</p>
        <p>An account has been created for you. Please use the following credentials to log in:</p>
        <ul>
          <li><strong>Username:</strong> {username}</li>
          <li><strong>Temporary Password:</strong> <code>{password}</code></li>
        </ul>
        <p>For security, you will be required to change this password upon your first login.</p>
        <p>Thank you.</p>
      </body>
    </html>
    """

    # Turn these into plain/html MIMEText objects
    part1 = MIMEText(text, "plain")
    part2 = MIMEText(html, "html")

    # Add HTML/plain-text parts to MIMEMultipart message
    message.attach(part1)
    message.attach(part2)

    try:
        # Create secure connection with server and send email
        context = smtplib.ssl.create_default_context()
        with smtplib.SMTP(mail_server, mail_port) as server:
            server.starttls(context=context)
            server.login(mail_username, mail_password)
            server.sendmail(sender_email, recipient_email, message.as_string())
        current_app.logger.info(f"Successfully sent password email to {recipient_email}")
    except Exception as e:
        current_app.logger.error(f"Failed to send email to {recipient_email}: {e}")
