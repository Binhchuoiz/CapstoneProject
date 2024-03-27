from django.db.models.signals import post_save
from django.dispatch import receiver
from firstapp.models import CVE,User
from .alert_tele import send_message_telegram



@receiver(post_save, sender=CVE)
def new_cve_noti(sender, instance , created , **kwargs):
    if created:
        send_message_telegram("new cve created")
    
