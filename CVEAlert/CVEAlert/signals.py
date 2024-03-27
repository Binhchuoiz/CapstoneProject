from django.db.models.signals import post_save
from django.dispatch import receiver
from firstapp.models import CVE,User
from django.dispatch import Signal
from .alert_tele import send_message_telegram

cve_Updated = Signal()

# @receiver(post_save, sender=CVE)
@receiver(cve_Updated)
def new_cve_noti(sender, **kwargs):
        send_message_telegram("new cve created")
    
