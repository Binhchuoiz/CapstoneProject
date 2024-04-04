from django.db.models.signals import post_save
from django.dispatch import receiver,Signal

from .alert_tele import send_message_telegram , reformat_tele_message
from firstapp.models import CVE , CvssV31 , Descriptions , User, Metric ,Follow_Affected,Affected
from accounts.models import NotiUser
from .alert_email import send_email
cve_Updated = Signal()

# @receiver(cve_Updated)
# def new_cve_noti(sender, **kwargs):
@receiver(post_save, sender=Metric)
def new_cve_noti(sender, instance, created, **kwargs):   
        metric=instance
        cve = CVE.objects.get(id=metric.con_id)
        try:
                descriptions = Descriptions.objects.get(con_id=metric.con_id)
        except Descriptions.DoesNotExist:
                descriptions = None    
        try:
                cvssv31 = CvssV31.objects.get(id=metric.cvssv31_id)
        except:
                cvssv31 = None
        subscribed_users = []
        affected_entities = Affected.objects.filter(con=cve)
        for affected_entity in affected_entities:
            subscribed_users += Follow_Affected.objects.filter(affected=affected_entity).values_list('user_id', flat=True).distinct()
        message = reformat_tele_message(cve.cve_id, cvssv31.base_score, descriptions, cve.id)
        for user_id in subscribed_users:
                noti_user = NotiUser.objects.get(pk=user_id)
                if noti_user.status== "telegram" or noti_user.status == "all":
                                if   noti_user.token_bot and noti_user.chat_id:
                                        chat_id = noti_user.chat_id
                                        token = noti_user.token_bot
                                send_message_telegram(message,token,chat_id)
                                if noti_user.status == "gmail" or noti_user.status=="all":
                                        if noti_user.email_address:
                                                send_email(message, noti_user.email_address)
        
    
