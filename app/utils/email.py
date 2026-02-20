from app.core.config import settings

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import smtplib
import socket

def send_email(to_email: str, subject: str, body: str):

    sender_email = settings.APP_EMAIL
    sender_password = settings.EMAIL_PASSWORD

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "html"))
    server = smtplib.SMTP("smtp.gmail.com", 587, timeout=10)
    server.starttls()
    server.login(sender_email, sender_password)
    server.send_message(msg)
    server.quit()
    
def send_recovery_otp(to_email: str, otp: str):
    subject = "Your OTP for Password Recovery"
    body = f"Your OTP for password recovery is: {otp}. It will expire in {settings.OTP_EXPIRE_MINUTES} minutes."

    send_email(to_email, subject, body)

def send_signup_otp(to_email: str, otp: str):

    subject = "Your OTP for Signup"
    body = f"Your OTP for signup is: {otp}. It will expire in {settings.OTP_EXPIRE_MINUTES} minutes."
    try:
        send_email(to_email, subject, body)
    except Exception:
        print("⚠️ Skipping email sending (Offline or Error)")
        print("requested otp: ",otp)
    
