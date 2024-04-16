import smtplib
import ssl 
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(body,to_email):
    subject= "CVE DAILY ALERT: PRODUCTS U FOLLOW HAVE A NEW CVE"

    smtp_server = "smtp.gmail.com"
    port = 465
    sender_email = "hienvdhe161853@fpt.edu.vn"
    password = "pjvr dtiv kfpy rilu"
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] =to_email
    message["From"] = subject

    message.attach(MIMEText(body,"plain"))

    context=ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server,port,context=context) as server:
        server.login(sender_email,password)

        server.sendmail(sender_email,to_email,message.as_string())

# def format_cve_alert_gmail(product, title, cvssv20=None, cvssv30=None, cvssv31=None, description=None, pk=None):
#     # Function to determine severity level based on CVSS score
#     def get_severity(score):
#         if score is None:
#             return None
#         score = float(score)
#         if score < 3:
#             return "Low"
#         elif 3 <= score <= 6:
#             return "Medium"
#         elif 6.1 <= score <= 8:
#             return "High"
#         else:
#             return "Critical"

#     # Function to generate HTML for colored text
#     def color_text(text, color):
#         return f'<span style="color: {color};">{text}</span>'

#     # Format the message
#     message = '<b>CVE\'s daily alert</b><br/><br/>'
#     message += f'Products you have follows: <i>{product}</i> have a new <b>CVE</b><br/>'
#     message += f'Name CVE: <i>{title}</i><br/>'
#     if cvssv20:
#         cvssv20_severity = get_severity(cvssv20)
#         cvssv20_color = {'Low': 'green', 'Medium': 'yellow', 'High': 'orange', 'Critical': 'red'}.get(cvssv20_severity, 'black')
#         message += f'Severity Score (CVSSv2.0): {color_text(cvssv20_severity, cvssv20_color)} - {cvssv20}<br/>'
#     if cvssv30:
#         cvssv30_severity = get_severity(cvssv30)
#         cvssv30_color = {'Low': 'green', 'Medium': 'yellow', 'High': 'orange', 'Critical': 'red'}.get(cvssv30_severity, 'black')
#         message += f'Severity Score (CVSSv3.0): {color_text(cvssv30_severity, cvssv30_color)} - {cvssv30}<br/>'
#     if cvssv31:
#         cvssv31_severity = get_severity(cvssv31)
#         cvssv31_color = {'Low': 'green', 'Medium': 'yellow', 'High': 'orange', 'Critical': 'red'}.get(cvssv31_severity, 'black')
#         message += f'Severity Score (CVSSv3.1): {color_text(cvssv31_severity, cvssv31_color)} - {cvssv31}<br/>'
#     if description:
#         message += f'Description: {description}<br/>'
#     if pk:
#         message += f'Url: <a href="http://127.0.0.1:8000/detail-cve/{pk}">CVE Details</a><br/>'
    
#     return message
