from django.db.models.signals import post_save
from django.dispatch import receiver,Signal

from .alert_tele import send_message_telegram , reformat_tele_message
from firstapp.models import CVE , CvssV31 , Descriptions , User, Metric ,Follow_Affected
from accounts.models import NotiUser
from .alert_email import send_email
cve_Updated = Signal()

# @receiver(cve_Updated)
# def new_cve_noti(sender, **kwargs):
@receiver(post_save, sender=CVE)
def new_cve_noti(sender, instance, created, **kwargs):   
        cve=instance
        try:
                metric = Metric.objects.filter(con_id = cve.id)
        except:
                metric = None
        cvss31 = [m.cvssv31 for m in metric]
        try:
                descriptions = Descriptions.objects.get(con_id=cve.id)
        except Descriptions.DoesNotExist:
                descriptions = None
        # subscribed_user = Follow_Affected.objects.filter(affected__con=cve).values_list('user_id',flat=True).distinct()
        message = reformat_tele_message(cve.cve_id, cvss31, descriptions , cve.id)
        # noti_user = NotiUser.objects.filter(user_id__in=subscribed_user)
        # chat_id= noti_user.chat_id
        # token = noti_user.token_bot
        print(descriptions)
        print(cvss31)
        print(message)
        # send_message_telegram(message)
        # send_email(message, "zdemon2002@gmail.com")
        
    
