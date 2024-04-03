import requests
def reformat_tele_message(title, cvssv31,description,pk):
    message= """CVE's daily alert\nProducts u have follows have a new CVE\nName CVE:'{}'\nSeverity Score:'{}'\nDescription:'{}'\nUrl: http://127.0.0.1:8000/detail-cve/{}/""".format(title, cvssv31,description,pk)
    return message


def send_message_telegram(message,TOKEN,chat_id):
    # TOKEN="6148039463:AAEcC7W3rPBe63cSjiMb6uoW89SgdYt-YZs"
    # chat_id = "1312773494"
    urls = f"https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={chat_id}&text={message}"
    return requests.get(urls).json