from django.db.models.signals import post_save
from django.dispatch import receiver,Signal

from .alert_tele import send_message_telegram , reformat_tele_message
from firstapp.models import CVE , CvssV31 , Descriptions , User, Metric ,Follow_Product,Affected,CvssV20,CvssV30 , Products
from accounts.models import NotiUser
from .alert_email import send_email
# cve_Updated = Signal()

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
        try:
                cvssv30 = CvssV30.objects.get(id=metric.cvssv30_id)
        except:
                cvssv30 = None
        try:
                cvssv20 = CvssV20.objects.get(id=metric.cvssv20_id)
        except:
                cvssv20 = None
        
        affected_entities = Affected.objects.filter(con=cve).first()
        if affected_entities:
        # print("Number of affected entities:",affected_entities.id)
                Follow_products = Follow_Product.objects.filter(product=affected_entities.product)
        product = Products.objects.filter(id__in=Follow_products).first()
        # print("Number of affected follow:",Follow_products.count())
        
        subscribed_users = NotiUser.objects.filter(user__in= Follow_products.values_list('user',flat=True))
        # print(subscribed_users)
        message = reformat_tele_message(product.name, cve.cve_id,cvssv20.base_score,cvssv30.base_score, cvssv31.base_score, descriptions, cve.id)
        for user in subscribed_users:
                
                if user.status == "telegram" :
                                if   user.token_bot and user.chat_id:
                                        
                                        send_message_telegram(message,user.token_bot,user.chat_id)
                elif user.status == "gmail" :
                                if user.email_address:
                                        
                                        send_email(message, user.email_address)
                if user.status == "all":
                        if   user.token_bot and user.chat_id:
                                       
                                        send_message_telegram(message,user.token_bot,user.chat_id)
                        if user.email_address:
                                       
                                        send_email(message, user.email_address)

        
    
