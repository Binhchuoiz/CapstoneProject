import smtplib
import ssl 
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(body,to_email):
    subject= "CVE DAILY ALERT: PRODUCTS U FOLLOW HAVE A NEW CVE"

    smtp_server = "smtp.gmail.com"
    port = 465
    sender_email = "binhndhe161032@gmail.com"
    password = "thbs bola rfxt gylx"
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] =to_email
    message["From"] = subject

    message.attach(MIMEText(body,"plain"))

    context=ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server,port,context=context) as server:
        server.login(sender_email,password)

        server.sendmail(sender_email,to_email,message.as_string())