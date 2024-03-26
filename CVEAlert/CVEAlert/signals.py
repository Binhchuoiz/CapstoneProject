from django.db.models.signals import post_save
from django.dispatch import receiver
from firstapp.models import CVE,User

@receiver(post_save, sender=CVE)
def new_cve_noti(sender, instance , created , **kwargs)
    if created:
        user_to_notify = User.objects.all
    
