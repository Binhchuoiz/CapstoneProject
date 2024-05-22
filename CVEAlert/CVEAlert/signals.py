from django.db.models.signals import post_save
from django.dispatch import receiver

from .alert_tele import send_message_telegram, format_cve_alert_telegram
from firstapp.models import CVE, CvssV31, Descriptions, Metric, Follow_Product, Affected, CvssV20, CvssV30, Products
from accounts.models import NotiUser
from .alert_email import send_email

@receiver(post_save, sender=Metric)
def new_cve_noti(sender, instance, created, **kwargs):
    if not created:
        return  # If the instance isn't new, you may not want to trigger this alert

    metric = instance
    cve = CVE.objects.filter(id=metric.con_id).first()
    if not cve:
        return  # Exit if no CVE found

    descriptions = Descriptions.objects.filter(con_id=metric.con_id).first()

    cvssv31 = CvssV31.objects.filter(id=metric.cvssv31_id).first()
    cvssv30 = CvssV30.objects.filter(id=metric.cvssv30_id).first()
    cvssv20 = CvssV20.objects.filter(id=metric.cvssv20_id).first()

    affected_entities = Affected.objects.filter(con=cve).first()
    if not affected_entities or not affected_entities.product:
        return  # Exit if no affected entities or no linked product

    follow_products = Follow_Product.objects.filter(product=affected_entities.product)
    product = Products.objects.filter(id__in=follow_products.values_list('product_id', flat=True)).first()
    if not product:
        return  # Exit if no product found after filtering

    # Assuming cvss scores could be None, handle these cases in your message formatting function
    message = format_cve_alert_telegram(product.name, cve.cve_id, 
                                        getattr(cvssv20, 'base_score', 'N/A'), 
                                        getattr(cvssv30, 'base_score', 'N/A'), 
                                        getattr(cvssv31, 'base_score', 'N/A'), 
                                        cve.id)

    subscribed_users = NotiUser.objects.filter(user__in=follow_products.values_list('user', flat=True))

    for user in subscribed_users:
        if user.status == "telegram" and user.token_bot and user.chat_id:
            send_message_telegram(message, user.token_bot, user.chat_id)
        elif user.status == "gmail" and user.email_address:
            send_email(message, user.email_address)
        elif user.status == "all":
            if user.token_bot and user.chat_id:
                send_message_telegram(message, user.token_bot, user.chat_id)
            if user.email_address:
                send_email(message, user.email_address)
