import requests
def reformat_tele_message(title, cvss31,description,pk):
    message= """""CVE's daily alert\nProducts u have follows have a new CVE\nName CVE:'{}'\nSeverity Score:'{}'\nDescription:'{}'\nUrl: http://127.0.0.1:8000/detail-cve/{}/""""".format(title, cvss31,description,pk)
    return message


def send_message_telegram(message):
    TOKEN="6730144543:AAGURAzKBs60Jf4VEKdw43nIcHBlPila-qc"
    chat_id = "1451532554"
    urls = f"https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={chat_id}&text={message}"
    return requests.get(urls).json