from django.shortcuts import render
from django.core.paginator import Paginator
from django.db import connection
from .models import CPE , CPE_distinct, CVE, CWE, metasploit_cve
import re, os, mimetypes, random, string
from django.http import HttpResponse
from datetime import datetime
from django.db import OperationalError


def index (request):
    cpe_s_list = CPE_distinct.objects.all()
    kol_vo = cpe_s_list.count()
    page = request.GET.get('page')

    paginator = Paginator(cpe_s_list, 20)
    page = request.GET.get('page')
    cpe_s = paginator.get_page(page)
    if (str(page) == "None"):
        page = 1
    # for cpe, id in zip(cpe_s,range(20)):
    #     cpe['id'] = id+1+(int(page)-1)*20
    return render(request, 'cpe/cpe.html', context={'cpe_s':cpe_s, 'kol_vo': kol_vo})

def home (request):
    return render(request, 'home/home.html')

def views_cve(request):
    cve_s = []
    id = str(request.path).split('/')[3]
    cursor = connection.cursor()
    #query = 'select distinct home_cpe.id, home_cpe.cve_name from home_cpe, home_cpe_distinct where home_cpe_distinct.CPE_name = home_cpe.CPE_name and home_cpe_distinct.id=%s'
    query = 'select cve_name from home_cpe where cpe_name = %s'
    cursor.execute(query, [id])
    row = cursor.fetchall()
    print(row)
    page = request.GET.get('page')
    kol_vo = len(row)
    print(kol_vo)
    for i in range(len(row)):
        cve_s_i = []
        cve_s_i.append(i+1)
        for a in row[i]:
            cve_s_i.append(a)
        cve_s.append(cve_s_i)
    print(cve_s)
    #print(cve_s[1])
    paginator = Paginator(cve_s, 20)
    page = request.GET.get('page')
    cve_s = paginator.get_page(page)
    context = {'kol_vo':kol_vo,
               'cve_s':cve_s}

    return render(request, 'views_cpe/views_cpe.html', context)

def about_cve(request):
    #global cve_s
    id = str(request.path).split('/')[-1]
    #print(id)
    cursor = connection.cursor()
    # query = 'select * from home_cve where CVE_name=%s'
    #query = 'select * from home_cve where cve_name = (select cve_name from home_cpe where cve_name = (select cve_name from home_cpe where id = %s))'
    query = 'select * from home_cve where cve_name = %s'
    cursor.execute(query,[str(id)])
    row = cursor.fetchall()
    query2 = 'select bdu_name from home_bdu where iden_name= %s'
    cursor.execute(query2, [row[0][1]])
    row2 = cursor.fetchall()
    # print(row)
    bdu_names = []
    for i in row2:
        bdu_names.append(str(i)[2:-3])
    if (len(bdu_names)==0): bdu_names.append('NONE')
    #print(row)
    description_title = str(row[0][3]).split('\n')[0].strip()
    print(description_title)
    description_tail = str(row[0][3]).split('\n')[-1].strip()
    #print(description_tail)
    vector = str(row[0][4]).split('(')[1].split(')')[0]
    date = str(row[0][2]).split(' ')[1]
    hyperlinks = ' '.join(str(row[0][7]).split('\n')).split(' ')[3::4]
    #cwe = str(row[0][6]).split('(')[1].split(')')[0]
    try:
        cwe = re.search(r'CWE-\d+', str(row[0][6])).group(0)
    except:
        cwe = "NONE"
    links = []
    for link in hyperlinks:
        links.append(link.strip())
    #print(hyperlinks)
    context = {'data_cve' : row,
               'description_title': description_title,
               'description_tail': description_tail,
               'vector': vector,
               'date': date,
               'hyperlinks': links,
               'id':id,
               'cwe': cwe,
               'bdu_names': bdu_names}
    return render(request, 'about_cve/about_cve.html', context)

def about_cwe(request):
    cwe_name = request.path.split('/')[-1]
    cursor = connection.cursor()
    # query = 'select * from home_cve where CVE_name=%s'
    query = 'select * from home_cwe_description where CWE_name = %s'
    cursor.execute(query, [cwe_name])
    row = cursor.fetchall()
    if (len(row)==0):
        cwe = "CWE в базе отсутствует"
        return render(request, 'cwe_from_cve/cwe_from_cve.html', {'cwe':cwe})
    description = str(row[0][2]).strip()
    hyperlink = str(row[0][3]).strip()
    query1 = 'select CAPEC_name from home_cwe where CWE_name = %s'
    cursor.execute(query1, [cwe_name])
    row1 = cursor.fetchall()
    capec_names = []
    for capec in row1:
        capec = re.sub(r",", '', re.sub(r"'", '', str(capec)))[1:-1]
        capec_names.append(capec)
    #print(capec_names)
    cursor.execute('select CWE_name from home_cve where CWE_name LIKE %s', ['%'+cwe_name+'%'])
    cwe_name_full = cursor.fetchone()[0]
    name = str(re.findall(r"CWE-\d+", str(cwe_name_full)))[2:-2]
    context ={'cwe_name': str(cwe_name_full).strip(),
              'description': description,
              'hyperlink': hyperlink,
              'capec_names': capec_names,
              'name':name}
    return render(request, 'cwe_from_cve/cwe_from_cve.html', context)

def about_capec(request):
    capec_name = request.path.split('/')[-1]
    cursor = connection.cursor()
    # query = 'select * from home_cve where CVE_name=%s'
    query = 'select * from home_capec_description where CAPEC_name = %s'
    cursor.execute(query, [capec_name])
    row = cursor.fetchall()
    des = str(row[0][2]).strip()
    link = str(row[0][3]).strip()
    #att_ck_name = str(row[0][5]).strip()
    att_ck_name = []
    id_att_ck = []
    link_att_ck = []
    size = len(row)
    for i in range(size):
        att_ck_name.append(str(row[i][5]))
        id_att_ck.append(str(row[i][4]))
        link_att_ck.append(row[i][6])
    # link_att_ck = str(row[0][6]).strip()
    # id_att_ck = str(row[0][4]).strip()
    context = {'capec_name': capec_name,
               'des': des,
               'link': link,
               'att_ck_name':att_ck_name,
               'link_att_ck': link_att_ck,
               'id_att_ck': id_att_ck}
    return render(request, 'capec_from_cwe/capec_from_cwe.html', context)

def att_ck(request):
    id_att_ck = request.path.split('/')[-1]
    cursor = connection.cursor()
    query = 'select * from home_att_ck where id_att_ck = %s'
    cursor.execute(query, [id_att_ck])
    row = cursor.fetchall()
    #print(row)
    name_att_ck = str(row[0][2]).strip()
    description_att_ck = str(row[0][3]).strip()
    tactic = str(row[0][4]).strip()
    platform = str(row[0][5]).strip()
    permissions_required = str(row[0][6]).strip()
    effective_permissions = str(row[0][7]).strip()
    data_sources = str(row[0][8]).strip()
    defense_bypassed = str(row[0][9]).strip()
    version = str(row[0][10]).strip().split(':')[-1].strip()
    capec_id = []
    cursor = connection.cursor()
    query1 = 'select CAPEC_name from home_capec_description, home_att_ck where home_att_ck.id_att_ck = home_capec_description.id_ATT_CK and home_att_ck.id_att_ck=%s'
    cursor.execute(query1, [id_att_ck])
    row1 = cursor.fetchall()
    for capec in row1:
        capec = re.sub(r",", '', re.sub(r"'", '', str(capec)))[1:-1]
        capec_id.append(capec)
    context = {'id_att_ck': id_att_ck,
               'name_att_ck': name_att_ck,
               'description_att_ck': description_att_ck,
               'tactic': tactic,
               'platform': platform,
               'permissions_required': permissions_required,
               'effective_permissions': effective_permissions,
               'data_sources': data_sources,
               'defense_bypassed': defense_bypassed,
               'version': version,
               'capec_id': capec_id}
    return render(request, 'att_ck/att_ck.html', context)

def cve(request):
    cve = CVE.objects.all()
    page = request.GET.get('page')
    paginator = Paginator(cve, 20)
    page = request.GET.get('page')
    cve_s = paginator.get_page(page)
    vsego = CVE.objects.count()

    context = {'cve_s':cve_s,
               'vsego': int(vsego),
               }
    return render(request, 'cve/cve.html',context)

def cve_info(request):
    name = request.path.split('/')[-1]
    #print(name)
    cursor = connection.cursor()
    # query = 'select * from home_cve where CVE_name=%s'
    query = 'select * from home_cve where cve_name= %s'
    cursor.execute(query, [name])
    row = cursor.fetchall()
    if (len(row)==0):
        res = 'CVE в базе отсутствует'
        return render(request, 'cve_info/cve_info.html', {'res':res})

    query2 = 'select bdu_name from home_bdu where iden_name= %s'
    cursor.execute(query2, [name])
    row2 = cursor.fetchall()
    # print(row)
    bdu_names = []
    for i in row2:
        bdu_names.append(str(i)[2:-3])
    if (len(bdu_names) == 0): bdu_names.append('NONE')
    description_title = str(row[0][3]).split('\n')[0].strip()
    print(description_title)
    description_tail = str(row[0][3]).split('\n')[-1].strip()
    try:
        vector = str(row[0][4]).split('(')[1].split(')')[0]
    except:
        vector = 'NONE'
    date = str(row[0][2]).split(' ')[1]
    hyperlinks = ' '.join(str(row[0][7]).split('\n')).split(' ')[3::4]
    # cwe = str(row[0][6]).split('(')[1].split(')')[0]
    try:
        cwe = re.search(r'CWE-\d+', str(row[0][6])).group(0)
    except:
        cwe = "NONE"
    links = []
    for link in hyperlinks:
        links.append(link.strip())
    # print(hyperlinks)
    context = {'data_cve': row,
               'description_title': description_title,
               'description_tail': description_tail,
               'vector': vector,
               'date': date,
               'hyperlinks': links,
               'id': id,
               'cwe': cwe,
               'bdu_names': bdu_names}
    return render(request, 'cve_info/cve_info.html', context)

def search(request):
    q = str(request.GET.get('q'))
    #print(q)
    cursor = connection.cursor()
    # query = 'select * from home_cve where CVE_name=%s'
    query = 'select id, cve_name, description from home_cve where cve_name like %s'
    cursor.execute(query, ['%' + q + '%'])
    row = cursor.fetchall()
    #print(row)
    page = request.GET.get('page')
    paginator = Paginator(row, 20)
    page = request.GET.get('page')
    cve_s = paginator.get_page(page)
    context = {'cve_s':cve_s,
               'last_questions': 'q=%s' % q}
    return render(request, 'search_cve/search_cve.html', context)

def search_cpe(request):
    q = str(request.GET.get('q'))
    #print(q)
    cursor = connection.cursor()
    # query = 'select * from home_cve where CVE_name=%s'
    query = 'select id, cpe_name from home_cpe_distinct where cpe_name like %s'
    cursor.execute(query, ['%' + q + '%'])
    row = cursor.fetchall()
    #print(row)
    page = request.GET.get('page')
    paginator = Paginator(row, 20)
    page = request.GET.get('page')
    cpe_s = paginator.get_page(page)
    context = {'cpe_s': cpe_s,
               'last_questions': 'q=%s' % q}
    return render(request, 'search_cpe/search_cpe.html', context)

def cwe(request):
    cursor = connection.cursor()
    # query = 'select * from home_cve where CVE_name=%s'
    query = 'select home_cwe_distinct.id, cwe_name, CWE_description from home_cwe_description home_cwe_distinct '
    cursor.execute(query)
    row = cursor.fetchall()
    #print(row)
    page = request.GET.get('page')
    paginator = Paginator(row, 20)
    page = request.GET.get('page')
    cwe_s = paginator.get_page(page)
    vsego = len(row)


    context = {'cwe_s':cwe_s,
               'vsego': int(vsego),
               }
    return render(request, 'cwe/cwe.html',context)

def search_cwe(request):
    q = str(request.GET.get('q'))
    # print(q)
    cursor = connection.cursor()
    # query = 'select * from home_cve where CVE_name=%s'
    query = 'select id, cwe_name, cwe_description from home_cwe_description where cwe_name like %s'
    cursor.execute(query, ['%' + q + '%'])
    row = cursor.fetchall()
    #print(row)
    page = request.GET.get('page')
    paginator = Paginator(row, 20)
    page = request.GET.get('page')
    cwe_s = paginator.get_page(page)
    context = {'cwe_s': cwe_s,
               'last_questions': 'q=%s' % q}
    return render(request, 'search_cwe/search_cwe.html', context)

def capec(request):
    cursor = connection.cursor()
    # query = 'select * from home_cve where CVE_name=%s'
    query = 'select * from home_capec_distinct '
    #print(query)
    cursor.execute(query)
    row = cursor.fetchall()
    print(row)
    page = request.GET.get('page')
    paginator = Paginator(row, 20)
    page = request.GET.get('page')
    capec_s = paginator.get_page(page)
    vsego = len(row)

    context = {'capec_s': capec_s,
               'vsego': int(vsego),
               }
    return render(request, 'capec/capec.html', context)

def search_capec(request):
    q = str(request.GET.get('q'))
    # print(q)
    cursor = connection.cursor()
    # query = 'select * from home_cve where CVE_name=%s'
    query = 'select * from home_capec_distinct where capec_name like %s order by capec_name asc'
    cursor.execute(query, ['%' + q + '%'])
    row = cursor.fetchall()
    #print(row)
    page = request.GET.get('page')
    paginator = Paginator(row, 20)
    page = request.GET.get('page')
    capec_s = paginator.get_page(page)
    context = {'capec_s': capec_s,
               'last_questions': 'q=%s' % q}
    return render(request, 'search_capec/search_capec.html', context)

def att_ck_all(request):
    cursor = connection.cursor()
    # query = 'select * from home_cve where CVE_name=%s'
    query = 'select id, name_att_ck, description_att_ck, id_att_ck from home_att_ck'
    cursor.execute(query)
    row = cursor.fetchall()
    page = request.GET.get('page')
    paginator = Paginator(row, 20)
    page = request.GET.get('page')
    att_ck = paginator.get_page(page)
    vsego = len(row)

    context = {'att_ck': att_ck,
               'vsego': int(vsego),
               }
    return render(request, 'att_ck_all/att_ck_all.html', context)

def search_att_ck_all(request):
    q = str(request.GET.get('q'))
    # print(q)
    cursor = connection.cursor()
    # query = 'select * from home_cve where CVE_name=%s'
    query = 'select id, name_att_ck, description_att_ck, id_att_ck from home_att_ck where name_att_ck like %s'
    cursor.execute(query, ['%' + q + '%'])
    row = cursor.fetchall()
    #print(row)
    page = request.GET.get('page')
    paginator = Paginator(row, 20)
    page = request.GET.get('page')
    att_ck = paginator.get_page(page)
    context = {'att_ck': att_ck,
               'last_questions': 'q=%s' % q}
    return render(request, 'search_att_ck_all/search_att_ck_all.html', context)

def infograf(request):
    name_list = ['(CWE-79)', '(CWE-119)','(CWE-20)','(CWE-200)','(CWE-89)','(CWE-264)','(CWE-22)','(CWE-399)','(CWE-352)','(CWE-310)']
    kol_vo = ['12889', '12592','8344','6521','5842','5786','3162','2964','2547','2534']
    name_list_cve=['CVE-1999-0524','CVE-2019-20079','CVE-2015-1209','CVE-2015-1210','CVE-2015-1211','CVE-2015-1212','CVE-2014-3166','CVE-2015-1233','CVE-2015-1234','CVE-2014-1730',]
    kol_vo_cve=['8223','7512','6976','6976','6976','6976','6947','6866','6866','6795']
    base_score_list=['11409','73402','45862']
    now = datetime.now()
    date_time = now.strftime("%d.%m.%Y")
    print(date_time)
    context = {'name_list': name_list[0:10],
               'kol_vo': kol_vo,
               'name_list_cve': name_list_cve,
               'kol_vo_cve': kol_vo_cve,
               'base_score_list' : base_score_list}

    if (request.GET.get('refresh')=='Click'):
        cursor = connection.cursor()
        # query = 'select * from home_cve where CVE_name=%s'
        query = 'select CWE_name, count(CWE_name) as count from home_cve group by CWE_name ORDER by count DESC'
        cursor.execute(query)
        graf_cwe = cursor.fetchall()
        name_list = []
        kol_vo = []
        for i in range(13):
            line = "(CWE-"+str(graf_cwe[i][0]).split("CWE-")[-1]
            if (line != '(CWE-Other)' and line != '(CWE-noinfo)' and line != '(CWE-NONE'):
                name_list.append(line)
                kol_vo.append(graf_cwe[i][1])
        query1 = 'select CVE_name , count (CVE_name) as count from home_cpe GROUP by CVE_name ORDER by count DESC'
        cursor.execute(query1)
        graf_cve = cursor.fetchall()
        kol_vo_cve = []
        name_list_cve = []
        for i in range(10):
            line = str(graf_cve[i+1][0]).strip()
            name_list_cve.append(line)
            kol_vo_cve.append(graf_cve[i+1][1])
        query2 = 'select DISTINCT  (SELECT  count (Description) from home_cve where Description REGEXP "[0-9].[0-9] LOW") as count_low,  (SELECT  count (Description) from home_cve where Description REGEXP "[0-9].[0-9] MEDIUM")as count_medium, (SELECT  count (Description) from home_cve where Description REGEXP "[0-9].[0-9] HIGH")as count_high from home_cve'
        cursor.execute(query2)
        base_score = cursor.fetchall()
        base_score_list = []
        for i in base_score[0]:
            base_score_list.append(i)
        now = datetime.now()
        date_time = now.strftime("%d.%m.%Y")
        print(date_time)
        context = {'name_list': name_list[0:10],
                   'kol_vo': kol_vo,
                   'name_list_cve': name_list_cve,
                   'kol_vo_cve': kol_vo_cve,
                   'base_score_list': base_score_list,
                   'date_time':date_time}
        return render(request, 'graf/graf.html', context)
    return render(request, 'graf/graf.html', context)

def cpes(request):
    name = request.path.split('_')[-1].split('/')[0]
    #print(name)
    #cpe_s_list = CPE.objects.filter(CVE_name__exact=name)
    cursor = connection.cursor()
    query = 'select home_cpe_distinct.* from home_cpe, home_cpe_distinct where home_cpe.CPE_name=home_cpe_distinct.CPE_name and  home_cpe.cve_name = %s'
    cursor.execute(query, [name])
    cpe_s_list = cursor.fetchall()
    # print(cpe_s_list)
    #kol_vo = cpe_s_list.count()
    kol_vo = len(cpe_s_list)
    page = request.GET.get('page')

    paginator = Paginator(cpe_s_list, 20)
    page = request.GET.get('page')
    cpe_s = paginator.get_page(page)
    if (str(page) == "None"):
        page = 1
    # for cpe, id in zip(cpe_s,range(20)):
    #     cpe['id'] = id+1+(int(page)-1)*20
    return render(request, 'cpe/cpe.html', context={'cpe_s': cpe_s, 'kol_vo': kol_vo})

def cves(request):
    name = str(request.path.split('_')[-1])[0:-1]
    #print(name)
    cwe = CVE.objects.filter(CWE_name__contains=name)
    #print(cwe)
    page = request.GET.get('page')
    paginator = Paginator(cwe, 20)
    page = request.GET.get('page')
    cve_s = paginator.get_page(page)
    vsego = CVE.objects.filter(CWE_name__contains=name).count()

    context = {'cve_s': cve_s,
               'vsego': int(vsego),
               }
    return render(request, 'cve/cve.html', context)

def capecs(request):
    name = str(request.path.split('_')[-1])[0:-1]
    #print(name)
    cursor = connection.cursor()
    query = 'select home_cwe_distinct.id, home_cwe.cwe_name, home_cwe_description.CWE_description from home_cwe_description, home_cwe_distinct, home_cwe where home_cwe_distinct.CWE_name = home_cwe_description.CWE_name and home_cwe_description.CWE_name = home_cwe.CWE_name and home_cwe.CAPEC_name = %s'
    cursor.execute(query, [name])
    row = cursor.fetchall()
    #capec = CWE.objects.filter(CAPEC_name__exact=name)
    # print(cwe)
    page = request.GET.get('page')
    paginator = Paginator(row, 20)
    page = request.GET.get('page')
    cwe_s = paginator.get_page(page)
    vsego = len(row)

    context = {'cwe_s': cwe_s,
               'vsego': int(vsego),
               }
    return render(request, 'cwe/cwe.html', context)

def bdu_fstec(request):
    cursor = connection.cursor()
    query = 'select distinct Идентификатор, Описаниеуязвимости, Уровеньопасностиуязвимости from bdu '
    cursor.execute(query)
    row = cursor.fetchall()
    bdu_list = []
    cvss2 = []
    k=0
    for i in list(row):
        cvss2.append(': '.join(str(row[k][2]).split(' ')[0:9:8]).split(')')[0])
        k=k+1
        bdu_list.append(list(i))
    for i in range(len(row)):
        bdu_list[i].append(i+1)
        bdu_list[i].append(cvss2[i])

    page = request.GET.get('page')
    paginator = Paginator(bdu_list, 20)
    page = request.GET.get('page')
    bdu_s = paginator.get_page(page)
    vsego = len(row)

    context = {'bdu_s': bdu_s,
               'vsego': int(vsego),
               }
    return render(request, 'bdu_fstec/bdu_fstec.html', context)

def search_bdu(request):
    q = str(request.GET.get('q'))
    # print(q)
    cursor = connection.cursor()
    query = 'select distinct Идентификатор, Описаниеуязвимости, Уровеньопасностиуязвимости from bdu where Идентификатор like %s'
    cursor.execute(query, ['%' + q + '%'])
    row = cursor.fetchall()
    bdu_list = []
    cvss2 = []
    k = 0
    for i in list(row):
        cvss2.append(': '.join(str(row[k][2]).split(' ')[0:9:8]).split(')')[0])
        k = k + 1
        bdu_list.append(list(i))
    for i in range(len(row)):
        bdu_list[i].append(i + 1)
        bdu_list[i].append(cvss2[i])

    page = request.GET.get('page')
    paginator = Paginator(bdu_list, 20)
    page = request.GET.get('page')
    bdu_s = paginator.get_page(page)
    vsego = len(row)
    context = {'bdu_s': bdu_s,
               'vsego': int(vsego),
               'last_questions': 'q=%s' % q}
    return render(request, 'search_bdu/search_bdu.html', context)

def bdu(request):
    name = request.path.split('/')[-2]
    cursor = connection.cursor()
    # query = 'select * from home_cve where CVE_name=%s'
    query = 'select bdu.* from  bdu where Идентификатор = %s'
    cursor.execute(query, [name])
    row = cursor.fetchall()
    bdu_name = str(row[0][0]).strip()
    date = str(row[0][9]).strip()
    des = str(row[0][2]).strip()
    vector = str(row[0][10]).strip()
    lvl = str(row[0][12]).split(')')[0]+')'
    cve = str(row[0][18]).split(',')
    cve_s = []
    for i in cve:
        if (str(re.findall(r"CVE-", str(i)))=="['CVE-']"):
            cve_s.append(i.strip())
    # for i in range(len(row)):
    #     cve_s.append(row[i][1])
    cwe_names = str(row[0][-1]).split(',')
    cwe_name = []
    for i in cwe_names:
        cwe_name.append(i.strip())
    links = str(row[0][17]).split('\n')
    link = []
    for i in links:
        link.append(i.strip())
    vendor = str(row[0][3]).strip()
    naz_po = str(row[0][4]).strip()
    ver_po = str(row[0][5]).strip()
    context = {'bdu_name': bdu_name,
               'date': date,
               'des': des,
               'vector':vector,
               'lvl': lvl,
               'cve_s': cve_s,
               'cwe_name': cwe_name,
               'link': link,
               'vendor': vendor,
               'naz_po': naz_po,
               'ver_po': ver_po}
    return render(request, 'bdu/bdu.html', context)

def metasploit(request):

    mets = metasploit_cve.objects.all()
    kol_vo = mets.count()
    page = request.GET.get('page')
    paginator = Paginator(mets, 20)
    page = request.GET.get('page')
    met = paginator.get_page(page)

    context = {'met':met,
               'kol_vo':kol_vo}
    return render(request, 'metaspoit/metasploit.html', context)

def sql(request):
    if (request.GET.get('q')!=None):
        try:
            q = str(request.GET.get('q'))
            print(str(q))
            now = datetime.now()  # current date and time
            date_time = now.strftime("(%H-%M)%d-%m-%Y")
            name_sql = str(date_time) + '.csv'
            q = q.upper()
            if (q.find('DELETE')!=-1):
                print('error ', q)
                return render(request, 'home/home.html', {'res':'Попробуйте снова (Запрещены CREATE DELETE INSERT): ', 'q':q})
            elif (q.find('INSERT')!=-1):
                print('error ', q)
                return render(request, 'home/home.html', {'res':'Попробуйте снова (Запрещены CREATE DELETE INSERT): ', 'q':q})
            elif (q.find('CREATE')!=-1):
                print('error ', q)
                return render(request, 'home/home.html', {'res':'Попробуйте снова (Запрещены CREATE DELETE INSERT): ', 'q':q})
            cursor = connection.cursor()
            cursor.execute(str(q))
            row = cursor.fetchall()
            fp = open(name_sql, "a", encoding="utf-8")
            for i in row:
                #print(str(i))
                fp.write(str(i)+';\n')
            fp.close()
            fp_ = open(name_sql, "rb")
            response = HttpResponse(fp_.read())
            fp_.close()
            file_type = mimetypes.guess_type(name_sql)
            if file_type is None:
                file_type = 'application/octet-stream'
            response['Content-Type'] = file_type
            response['Content-Length'] = str(os.stat(name_sql).st_size)
            response['Content-Disposition'] = "attachment; filename="+name_sql
            os.remove(name_sql)
            return response
        except OperationalError:
            return render(request, 'home/home.html', {'res': 'Ошибка: ', 'q':'неправильно сформирован SQL-запрос. Попробуйте снова'})
    return render(request, 'home/home.html')
#select description from home_cve where cve_name="CVE-2010-3782";




