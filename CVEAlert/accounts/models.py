from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='user_profile')
	dob = models.CharField(blank=True, max_length=225)
	phone_number = models.CharField(max_length=225, blank=True)
	full_name = models.CharField(max_length=225, blank=True)
	email_profile = models.CharField(max_length=225, blank=True)

	def __str__(self):
		return str(self.user.username)
	
class NotiUser(models.Model):
	user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='user_notification')
	status = models.CharField(max_length=225, blank=True)
	email_address = models.EmailField(blank=True)
	token_bot = models.CharField(max_length=225, blank=True)
	chat_id = models.CharField(max_length=225, blank=True)

	def __str__(self):
		return str(self.user.username)

