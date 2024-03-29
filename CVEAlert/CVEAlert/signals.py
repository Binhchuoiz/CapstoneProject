from django.db.models.signals import post_save
from django.dispatch import receiver,Signal

from .alert_tele import send_message_telegram , reformat_tele_message
from firstapp.models import CVE , CvssV31 , Descriptions , User, Metric
from accounts.models import NotiUser

cve_Updated = Signal()

# @receiver(cve_Updated)
# def new_cve_noti(sender, **kwargs):
@receiver(post_save, sender=CVE)
@receiver(post_save,sender=Metric)
def new_cve_noti(sender, instance, created, **kwargs):   
        cve=instance
        try:
                metric = Metric.objects.filter(con_id = cve.id)
        except:
                metric = None
        cvss31 = [m.cvssv31 for m in metric]
        try:
                descriptions = Descriptions.objects.get(id=cve.id)
        except Descriptions.DoesNotExist:
                descriptions = None
        message = reformat_tele_message(cve.cve_id, cvss31, descriptions , cve.id)
        send_message_telegram(message)
    
