from django import forms
from ckeditor.fields import RichTextField
from .models import CVE,Affected

class CVEform(forms.ModelForm):
    class Meta:
        model = CVE
        fields = '__all__'

        widgets = {
            'description' : RichTextField(config_name='default')
        }
class AffectedForm(forms.ModelForm):
    class Meta:
        model = Affected
        fields = '__all__'