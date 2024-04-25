from django.db import models
from accounts.models import User

class CVE(models.Model):
    cve_id = models.CharField(max_length=255, default="")
    year = models.CharField(max_length=255, default="")
    data_version = models.CharField(max_length=255, default="")
    data_type = models.CharField(max_length=255, default="")
    date_reserved = models.CharField(max_length=255, default="", null=True)
    date_publish = models.CharField(max_length=255, default="", null=True)
    date_update = models.CharField(max_length=255, default="", null=True)
    assigner_org_id = models.CharField(max_length=255, default="", null=True)
    assigner_short_name = models.CharField(max_length=900, default="", null=True)
    title = models.CharField(max_length=9000, default="", null=True)

    def __str__(self):
        return self.cve_id
    
class Descriptions(models.Model):
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='description_cves', blank=True, default=None)
    value = models.CharField(max_length=9000, default="", null=True)
    # lang = models.CharField(max_length=10, default="en")  # Add language field

    def __str__(self):
        return self.value
    
class Solutions(models.Model):
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='solutions_cves', blank=True, default=None)
    value = models.CharField(max_length=9000, default="", null=True)

    def __str__(self):
        return self.value
    
class Exploits(models.Model):
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='exploits_cves', blank=True, default=None)
    value = models.CharField(max_length=9000, default="", null=True)

    def __str__(self):
        return self.value

class ProblemTypes(models.Model):
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='problemtypes_cves', blank=True, default=None)
    cwe_id = models.CharField(max_length=255, default="", null=True)  # Update field name
    description = models.CharField(max_length=9000, default="", null=True)
    # lang = models.CharField(max_length=10, default="en")  # Add language field

    def __str__(self):
        return self.cwe_id

class Workaround(models.Model):
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='workaround_cves', blank=True, default=None)
    value = models.CharField(max_length=9000, default="", null=True)

    def __str__(self):
        return self.value

class Versions(models.Model):
    version = models.CharField(max_length=3000, default="", null=True)
    status = models.CharField(max_length=255, default="", null=True)
    type = models.CharField(max_length=255, default="", null=True)

    def __str__(self):
        return self.version
    
class Products(models.Model):
    name = models.CharField(max_length=3000, default="", null=True)

    def __str__(self):
        return self.name
    
class Vendors(models.Model):
    name = models.CharField(max_length=3000, default="", null=True)

    def __str__(self):
        return self.name
    
class Products_Versions(models.Model):
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='productversion_cves', blank=True, default=None)
    product = models.ForeignKey(Products, on_delete=models.CASCADE, related_name='product_version', blank=True, default=None)
    version = models.ForeignKey(Versions, on_delete=models.CASCADE, related_name='version_product', blank=True, default=None)
    
    def __str__(self):
        return self.product.name  # Return product name instead of object
    
# class Platforms(models.Model):
#     con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='platforms_cves', blank=True, default=None)
#     value = models.CharField(max_length=9000, default="", null=True)

#     def __str__(self):
#         return self.value

class Affected(models.Model):
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='affected_cves', blank=True, default=None)
    product = models.ForeignKey(Products, on_delete=models.CASCADE, related_name='product_vendor', blank=True, default=None)
    vendor = models.ForeignKey(Vendors, on_delete=models.CASCADE, related_name='vendor_product', blank=True, default=None)
    # platform = models.ForeignKey(Platforms, on_delete=models.CASCADE, related_name='affected_platform', blank=True, default=None)

    def __str__(self):
        return self.product.name  # Return product name instead of object
    
class References(models.Model):
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='references_cves', blank=True, default=None)
    url = models.CharField(max_length=3000, default="", null=True)

    def __str__(self):
        return self.url
    
class CvssV20(models.Model):
    version = models.CharField(max_length=255, default="", null=True)
    vector_string = models.CharField(max_length=300, default="", null=True)
    base_score = models.FloatField(default=0.0, null=True)  # Updated default value

    def __str__(self):
        return self.version
    
class CvssV30(models.Model):
    version = models.CharField(max_length=255, default="", null=True)
    vector_string = models.CharField(max_length=300, default="", null=True)
    base_score = models.FloatField(default=0.0, null=True)  # Updated default value
    base_severity = models.CharField(max_length=255, default="", null=True)

    def __str__(self):
        return self.version
    
class CvssV31(models.Model):
    attackComplexity = models.CharField(max_length=255, default="", null=True)
    attackVector = models.CharField(max_length=255, default="", null=True)
    availabilityImpact = models.CharField(max_length=255, default="", null=True)
    confidentialityImpact = models.CharField(max_length=255, default="", null=True)
    integrityImpact = models.CharField(max_length=255, default="", null=True)
    privilegesRequired = models.CharField(max_length=255, default="", null=True)
    scope = models.CharField(max_length=255, default="", null=True)
    userInteraction = models.CharField(max_length=255, default="", null=True)
    version = models.CharField(max_length=255, default="", null=True)
    vector_string = models.CharField(max_length=400, default="", null=True)
    base_score = models.FloatField(default=0.0, null=True)  # Updated default value
    base_severity = models.CharField(max_length=255, default="", null=True)

    def __str__(self):
        return self.version
    
class Metric(models.Model):
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='metric_cve', blank=True, default=None)
    cvssv20 = models.ForeignKey(CvssV20, on_delete=models.CASCADE, related_name='metric_cvss_v20', blank=True, default=None)
    cvssv30 = models.ForeignKey(CvssV30, on_delete=models.CASCADE, related_name='metric_cvss_v30', blank=True, default=None)
    cvssv31 = models.ForeignKey(CvssV31, on_delete=models.CASCADE, related_name='metric_cvss_v31', blank=True, default=None)
    
    def __str__(self):
        return str(self.con.id)  # Return CVE ID as string

class FollowProduct(models.Model):  # Renamed from Follow_Product
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='follow_user', blank=True, default=None)
    product = models.ForeignKey(Products, on_delete=models.CASCADE, related_name='follow_product', blank=True, default=None)

    def __str__(self):
        return self.user.username  # Return username
    
class FollowCVE(models.Model):  # Renamed from Follow_CVE
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_cve', blank=True, default=None)
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='follow_cve', blank=True, default=None)

    def __str__(self):
        return self.user.username  # Return username
