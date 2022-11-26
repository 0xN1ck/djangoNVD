from django.contrib import admin
from home.models import CPE, CVE, CWE, CWE_description, CAPEC_description, CPE_distinct, att_ck, CWE_distinct, CAPEC_distinct, metasploit_cve
admin.site.register(CPE)
admin.site.register(CVE)
admin.site.register(CWE)
admin.site.register(CWE_description)
admin.site.register(CAPEC_description)
admin.site.register(CPE_distinct)
admin.site.register(att_ck)
admin.site.register(CWE_distinct)
admin.site.register(CAPEC_distinct)
admin.site.register(metasploit_cve)
