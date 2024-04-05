from django.db.models.signals import post_save
from django.dispatch import receiver,Signal

from .alert_tele import send_message_telegram , reformat_tele_message
from firstapp.models import CVE , CvssV31 , Descriptions , User, Metric ,Follow_Product,Affected
from accounts.models import NotiUser
from .alert_email import send_email
# cve_Updated = Signal()

# @receiver(cve_Updated)
# def new_cve_noti(sender, **kwargs):
@receiver(post_save, sender=Metric)
def new_cve_noti(sender, instance, created, **kwargs):   
        print("invoked")
        metric=instance
        cve = CVE.objects.get(id=metric.con_id)
        try:
                descriptions = Descriptions.objects.get(con_id=metric.con_id)
        except Descriptions.DoesNotExist:
                descriptions = None    
        try:
                cvssv31 = CvssV31.objects.get(id=metric)
        except:
                cvssv31 = None
        print("invoked2")
        affected_entities = Affected.objects.filter(con=cve).first()
        if affected_entities:
                print("Number of affected entities:",affected_entities.id)
                Follow_products = Follow_Product.objects.filter(product=affected_entities.product)
        
        print("Number of affected follow:",Follow_products.count())
        # for affected_entity in affected_entities:
        subscribed_users = NotiUser.objects.filter(user__in= Follow_products.values_list('user',flat=True))
        print(subscribed_users)
        message = reformat_tele_message(cve.cve_id, cvssv31, descriptions, cve.id)
        for user in subscribed_users:
                # print(user.status)
                # print(user.chat_id)
                # print(user.token_bot)
                if user.status == "telegram" :
                                if   user.token_bot and user.chat_id:
                                        # print(user.chat_id)
                                        # print(user.token_bot)
                                        send_message_telegram(message,user.token_bot,user.chat_id)
                elif user.status == "gmail" :
                                if user.email_address:
                                        # print(user.email_address)
                                        send_email(message, user.email_address)
                if user.status == "all":
                        if   user.token_bot and user.chat_id:
                                        # print(user.chat_id)
                                        # print(user.token_bot)
                                        send_message_telegram(message,user.token_bot,user.chat_id)
                        if user.email_address:
                                        # print(user.email_address)
                                        send_email(message, user.email_address)

        
    
