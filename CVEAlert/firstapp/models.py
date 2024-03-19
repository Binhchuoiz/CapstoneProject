from django.db import models

class CVE(models.Model):
    cve_id = models.CharField(max_length=255, default="")
    year = models.CharField(max_length=255, default="")
    data_type = models.CharField(max_length=255, default="")
    data_version = models.CharField(max_length=255, default="")
    date_reserved = models.CharField(max_length=255, default="", null = True)
    date_publish = models.CharField(max_length=255, default="", null = True)
    date_update = models.CharField(max_length=255, default="", null = True)
    assigner_Org_Id = models.CharField(max_length=255, default="", null = True)
    provider_Metadata = models.CharField(max_length=255, default="", null = True)

    def __str__(self) -> str:
        return super(self.cve_id).__str__(self.cve_id)
    
class Descriptions(models.Model):
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='description_cves', blank=True, default=None)
    value = models.CharField(max_length=9000, default="", null = True)

    def __str__(self) -> str:
        return super(self.value).__str__(self.value)
    
class Solutions(models.Model):
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='solutions_cves', blank=True, default=None)
    value = models.CharField(max_length=9000, default="", null = True)

    def __str__(self) -> str:
        return super(self.value).__str__(self.value)
    
class Versions(models.Model):
    version = models.CharField(max_length=3000, default="", null = True)
    status = models.CharField(max_length=255, default="", null = True)

    def __str__(self) -> str:
        return super(self.version).__str__(self.version)
    
class Products(models.Model):
    name = models.CharField(max_length=3000, default="", null = True)

    def __str__(self) -> str:
        return super(self.name).__str__(self.name)
    
class Vendors(models.Model):
    name = models.CharField(max_length=3000, default="", null = True)

    def __str__(self) -> str:
        return super(self.name).__str__(self.name)
    
class Products_Versions(models.Model):
    product = models.ForeignKey(Products, on_delete=models.CASCADE, related_name='product_version', blank=True, default=None)
    version = models.ForeignKey(Versions, on_delete=models.CASCADE, related_name='version_product', blank=True, default=None)
    
    def __str__(self) -> str:
        return super(self.product).__str__(self.product)
    
class Affected(models.Model):
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='affected_cves', blank=True, default=None)
    product = models.ForeignKey(Products, on_delete=models.CASCADE, related_name='product_vendor', blank=True, default=None)
    vendor = models.ForeignKey(Vendors, on_delete=models.CASCADE, related_name='vendor_product', blank=True, default=None)

    def __str__(self) -> str:
        return super(self.product).__str__(self.product)
    
class References(models.Model):
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='references_cves', blank=True, default=None)
    url = models.CharField(max_length=3000, default="", null = True)

    def __str__(self) -> str:
        return super(self.url).__str__(self.url)
    
class CvssV20(models.Model):
    version = models.CharField(max_length=255, default="", null = True)
    vector_string = models.CharField(max_length=300, default="", null = True)
    base_score = models.FloatField(default="", null = True)

    def __str__(self) -> str:
        return super(self.version).__str__(self.version)
    
class CvssV30(models.Model):
    version = models.CharField(max_length=255, default="", null = True)
    vector_string = models.CharField(max_length=300, default="", null = True)
    base_score = models.FloatField(default="", null = True)
    base_severity = models.CharField(max_length=255, default="", null = True)

    def __str__(self) -> str:
        return super(self.version).__str__(self.version)
    
class CvssV31(models.Model):
    version = models.CharField(max_length=255, default="", null = True)
    vector_string = models.CharField(max_length=400, default="", null = True)
    base_score = models.FloatField(default="", null = True)
    base_severity = models.CharField(max_length=255, default="", null = True)

    def __str__(self) -> str:
        return super(self.version).__str__(self.version)
    
class Metric(models.Model):
    con = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name='metric_cve', blank=True, default=None)
    cvssv20 = models.ForeignKey(CvssV20, on_delete=models.CASCADE, related_name='metric_cvss_v20', blank=True, default=None)
    cvssv30 = models.ForeignKey(CvssV30, on_delete=models.CASCADE, related_name='metric_cvss_v30', blank=True, default=None)
    cvssv31 = models.ForeignKey(CvssV31, on_delete=models.CASCADE, related_name='metric_cvss_v31', blank=True, default=None)
    
    def __str__(self) -> str:
        return super(self.con).__str__(self.con)
# Create your models here.
