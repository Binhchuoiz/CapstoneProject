import requests


def send_message_telegram(message):
    TOKEN="6148039463:AAEcC7W3rPBe63cSjiMb6uoW89SgdYt-YZs"
    chat_id = "1312773494"
    urls = f"https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={chat_id}&text={message}"
    return requests.get(urls).json