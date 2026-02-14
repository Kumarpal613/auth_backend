from app.core.config import settings

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(to_email: str, subject: str, body: str):

    sender_email = settings.APP_EMAIL
    sender_password = settings.EMAIL_PASSWORD

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = to_email
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "html"))

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)


def send_otp_email(to_email:str, otp: str):
    subject = "Your OTP for Password Recovery"
    body = f"Your OTP for password recovery is: {otp}. It will expire in {settings.otp_expire_minutes} minutes."

    send_email(to_email, subject , body)