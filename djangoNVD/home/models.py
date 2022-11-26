from django.db import models

class CPE(models.Model):
    id = models.IntegerField(primary_key=True)
    CPE_name = models.TextField()
    CVE_name = models.TextField()

    def __str__(self):
        return str(self.CPE_name)

class CVE(models.Model):
    id = models.IntegerField(primary_key=True)
    CVE_name = models.TextField()
    Date1 = models.TextField()
    Description = models.TextField()
    CVSS_name = models.TextField()
    CVSS_description = models.TextField()
    CWE_name = models.TextField()
    Hyperlink = models.TextField()

    def __str__(self):
        return str(self.CVE_name)

class CWE(models.Model):
    id = models.IntegerField(primary_key=True)
    CWE_name = models.TextField()
    CAPEC_name = models.TextField()

    def __str__(self):
        return str(self.CWE_name)

class CWE_description(models.Model):
    id = models.IntegerField(primary_key=True)
    CWE_name = models.TextField()
    CWE_description = models.TextField()
    CWE_link = models.TextField()

    def __str__(self):
        return str(self.CWE_name)

class CAPEC_description(models.Model):
    id = models.IntegerField(primary_key=True)
    CAPEC_name = models.TextField()
    CAPEC_description = models.TextField()
    CAPEC_link = models.TextField()
    id_ATT_CK = models.TextField(default='NONE')
    ATT_CK_name = models.TextField(default='NONE')
    ATT_CK_link = models.TextField(default='NONE')

    def __str__(self):
        return str(self.CAPEC_name)

class CPE_distinct(models.Model):
    id = models.IntegerField(primary_key=True)
    CPE_name = models.TextField()
    def __str__(self):
        return str(self.CPE_name)

class att_ck(models.Model):
    id = models.IntegerField(primary_key=True)
    id_att_ck = models.TextField()
    name_att_ck = models.TextField()
    description_att_ck = models.TextField()
    tactic = models.TextField()
    platform = models.TextField()
    permissions_required = models.TextField()
    effective_permissions = models.TextField()
    data_sources = models.TextField()
    defense_bypassed = models.TextField()
    version = models.TextField()

    def __str__(self):
        return str(self.id_att_ck)

class CWE_distinct(models.Model):
    id = models.IntegerField(primary_key=True)
    CWE_name = models.TextField()
    def __str__(self):
        return str(self.CWE_name)

class CAPEC_distinct(models.Model):
    id = models.IntegerField(primary_key=True)
    CAPEC_name = models.TextField()
    CAPEC_description = models.TextField()
    def __str__(self):
        return str(self.CAPEC_name)

class metasploit_cve(models.Model):
    id = models.IntegerField(primary_key=True)
    way = models.TextField()
    CVE_name = models.TextField()
    def __str__(self):
        return str(self.CVE_name)