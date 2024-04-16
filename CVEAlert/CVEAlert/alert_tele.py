import requests
def reformat_tele_message1(product,title,cvssv20,cvssv30, cvssv31,description,pk):
    message = """CVE's daily alert\nProducts u have follows:'{}' have a new CVE\nName CVE:'{}'\nSeverity Score (CVSSv2.0):'{}'\nSeverity Score (CVSSv3.0):'{}'\nSeverity Score (CVSSv3.1):'{}'\nDescription:'{}'\nUrl: http://127.0.0.1:8000/detail-cve/{}""".format(product, title, cvssv20, cvssv30, cvssv31, description, pk)
    return message

def format_cve_alert_telegram(product, title, cvssv20, cvssv30, cvssv31, pk):
    # Define icons for different severity levels
    icons = {
        "low": "🟢",
        "medium": "⚠️",
        "high": "🔶",
        "critical": "❗️❗️❗️"
    }

    # Function to determine severity level based on CVSS score
    def get_severity(score):
        if score is None:
            return None
        score = float(score)
        if score < 3.9:
            return "low"
        elif 4 <= score <= 6.9:
            return "medium"
        elif 7.0 <= score <= 8.9:
            return "high"
        else:
            return "critical"

    # Format the message
    message = f"🔔 **New CVE's Alert** 🔔\n\n"
    message += f"➡️ Products you have follows: *{product}* have a new *CVE*\n"
    message += f"➡️ Name CVE: *{title}*\n"
    if cvssv20:
        cvssv20_severity = get_severity(cvssv20)
        message += f"➡️ Severity Score (CVSSv2.0): {cvssv20} {icons.get(cvssv20_severity)} ({cvssv20_severity})\n"
    if cvssv30:
        cvssv30_severity = get_severity(cvssv30)
        message += f"➡️ Severity Score (CVSSv3.0): {cvssv30} {icons.get(cvssv30_severity)} ({cvssv30_severity})\n"
    if cvssv31:
        cvssv31_severity = get_severity(cvssv31)
        message += f"➡️ Severity Score (CVSSv3.1): {cvssv31} {icons.get(cvssv31_severity)} ({cvssv31_severity})\n"
    if pk:
        message += f"➡️ Url: https://cvealert-cci98.ondigitalocean.app/detail-cve/{pk} \n"
    
    return message


def send_message_telegram(message,TOKEN,chat_id):
    urls = f"https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={chat_id}&text={message}"
    return requests.get(urls).json