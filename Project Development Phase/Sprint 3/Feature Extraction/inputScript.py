import regex
from tldextract import extract
import ssl
import socket
from bs4 import BeautifulSoup
import urllib.request
import whois
import datetime
import re
import requests
import validators
#1 
def url_having_ip(url):
    return 0
#2
def chec_ip_regularity(url):
    return 0

#3 
#URL based Features
#length of the URL
def check_url_length(url):
    url_length=len(url)
    if url_length<54:
        return -1
    elif 54<=url_length<=75:
        return 0
    else:
        return 1

#4
#shortening service
def url_sort(url):
    return 0

#5
def check_symbol_specification(url):

    symbol=regex.findall(r'@',url)
    if len(symbol)==0:
        return -1
    else:
        return 1

#6
def having_double_slash(url):
    return 0


#7
#domain based Feature
#count for domain
def check_prefix_suffix(url):
    print(type(url))
    subdomain,domain,suffix=extract(url)
    if domain.count('-'):
        return 1
    else:
        return -1

#8
#URL based Feature
#number of sub-domain in URL 
def check_subdomain(url):
    subdomain, domain, suffix = extract(url)
    if subdomain.count('.')==0:
        return -1
    elif subdomain.count('.')==1:
        return 0
    else:
        return 1

#9
#check the ssl certificate final state to avoid phishing
def check_SSL_finalstate(url):
    try:
        if regex.search('^https',url):
            used=1
        else:
            used=0
        subdomain, domain, suffix = extract(url)
        host_name=domain+"."+suffix
        context=ssl.create_default_context()
        sct=context.wrap_socket(socket.socket(),server_hostname=host_name)
        sct.connect((host_name,443))
        certificate=sct.getpeercert()
        issuer=dict(x[0] for x in certificate['issuer'])
        certificate_Auth=str(issuer['commonName'])
        certificate_Auth=certificate_Auth.split()
        if(certificate_Auth[0]=="Network" or certificate_Auth=="Deutsche"):
            certificate_Auth=certificate_Auth[0]+" "+certificate_Auth[1]
        else:
            certificate_Auth=certificate_Auth[0]
        trusted_Auth=['Comodo','Symantec','GoDaddy','Globalsign','Digicert','StartCom','Entrust','Verizon','Trustwave','Unizeto','Buypass','QuoVadis','Deutsche Telekom','Network Solutions','SwissSign','IdenTrust','Secom','TWCA','Geotrust','Thawte','Doster','VeriSign']
        startingdate=str(certificate['noBefore'])
        endingdate=str(certificate['noAfter'])
        startingYear=int(startingdate.split()[3])
        endingYear=int(endingdate.split()[3])
        Age_of_certificate=endingYear-startingYear
        if (used==1) and (certificate_Auth in trusted_Auth) and (Age_of_certificate>=1):
            return 1
        elif (used==1) and (certificate_Auth not in trusted_Auth):
            return 0
        else:
            return 1
    except Exception as e:
        return 1

#10
#Domain Based Feature
#How many days passed since the domain was registered?
def check_domain_registration(url):
    try:
        w=whois.whois(url)
        updated=w.updated_date
        exp=w.expiration_date
        length=(exp[0]-updated[0]).days
        if length<=365:
            return 1
        else:
            return -1
    except:
        return 0

#11
def favicon(url):
    return 0

#12
def port(url):
    return 0

#13
#check for https token in the url
def check_https_token(url):
    subdomain,domain,suffix=extract(url)
    host=subdomain+"."+domain+","+suffix
    if host.count('https'):
        return 1
    else:
        return -1

#14
def check_request_url(url):
    try:
        subdomain, domain, suffix = extract(url)
        websiteDomain=domain

        opener=urllib.request.urlopen(url).read()
        soup=BeautifulSoup(opener,'lxml')
        imgs=soup.findAll('img',src=True)
        total=len(imgs)

        linked=0
        avg=0
        for image in imgs:
            subdomain, domain, suffix = extract(image['src'])
            imageDomain=domain
            if websiteDomain==imageDomain or imageDomain=='':
                linked=linked+1
        vids=soup.findAll('vedio',src=True)
        total=total+len(vids)
        for video in vids:
            subdomain, domain, suffix = extract(video['src'])
            vidDomain=domain
            if websiteDomain == vidDomain or vidDomain == '':
                linked = linked + 1
            linked2=total-linked
            if total!=0:
                ag=linked2/total
            if avg<0.22:
                return -1
            elif(0.22<=avg<=0.61):
                return 0
            else:
                return 1
    except:
        return 0


#15
#shows the achor linking of that page
def chec_anchor(url):
    try:
        subdomain,domain,suffix=extract(url)
        websiteDomain=domain

        opener=urllib.request.urlopen(url).read()
        soup=BeautifulSoup(opener,'lxml')
        anchors=soup.findAll('a',href=True)
        total=len(anchors)
        linked=0
        avg=0
        for anchor in anchors:
            subdomain,domain,suffix=extract(anchors['href'])
            anchorDomain=domain
            if websiteDomain==anchorDomain or anchorDomain=='':
                linked=linked+1
            linked2=total-linked
            if total!=0:
                ang=linked2/total
            if avg<0.31:
                return -1
            elif 0.31<=avg<=0.67:
                return 0
            else:
                return 1
    except:
        return 0


#16
#checking for links an tags
def check_tags_links(url):
    try:
        opener=urllib.request.urlopen(url).read()
        soup=BeautifulSoup(opener,'lxml')

        meta=0
        link=0
        script=0
        anchors=0
        avg=0
        for meta in soup.find_all('meta'):
            meta=meta+1
        for link in soup.find_all('link'):
            link=link+1
        for script in soup.find_all('script'):
            script=script+1
        for anchor in soup.find_all('a'):
            anchors = anchors + 1
        total=meta=link+script+anchors
        tags=meta+link+script
        if total!=0:
            avg=tags/total

        if avg<0.25:
            return -1

        elif 0.25 <=avg<=0.81:
            return 0

        else:
            return 1
    except:
        return 1

#17
def sfh(url):
    return 0

#18
def check_email_submit(url):
    try:
        opener=urllib.request.urlopen(url).read()
        soup=BeautifulSoup(opener,'lxml')
        if soup.find('mailyo'):
            return 1
        else:
            return -1
    except:
        return 0

#19
def abnormal_url(url):
    if validators.url(url)==True:
        return 1
    else:
        return -1

#20
#redirect
def redirect(url):
    responses = requests.get(url)
    if responses.history==" ":
        return 1
    else:
        return -1
#21
def on_mouse_over(url):
    return 0

#22
def right_click(url):
    return 0

#23
def pop_up(url):
    return 0

#24
def iframe(url):
    return 0

#25
def checK_age_domain(url):
    try:
        w=whois(url)
        start_date=w.creation_date
        current_date=datetime.datetime.now()
        age=(current_date-start_date[0]).days
        if age>=180:
            return -1
        else:
            return 1
    except Exception as e:
        print(e)
        return 0

#26
def dns(url):
    return 0

#27
#Page Based Features
#WEb traffic share per country
def web_traffic(url):
    try:
        r = requests.head(url,verify=False,timeout=5) 
        if r.status_code==200:
            return 1
        else:
            return -1
    except:
        return 0

#28

def page_run(url):
    return 0

#29
#page based Feature
#checking if the url is indexed by google or not
def google_index(url):
    google = "https://www.google.com/search?q=site:" + url + "&hl=en"
    response = requests.get(google, cookies={"CONSENT": "YES+1"})
    soup = BeautifulSoup(response.content, "html.parser")
    not_indexed = re.compile("did not match any documents")

    if soup(text=not_indexed):
        return -1
    else:
        return 1

#30

def link_pointing(url):
    return 0

#31
def statistical(url):
    return 0



def main(url):
    print(url)
    check=[[url_having_ip(url),
          chec_ip_regularity(url),
          url_sort(url),
          check_symbol_specification(url),
          having_double_slash(url),
          check_prefix_suffix(url),
          check_subdomain(url),
          check_SSL_finalstate(url),
          check_domain_registration(url),
          favicon(url),
          port(url),
          check_https_token(url),
          check_request_url(url),
          chec_anchor(url),
          check_tags_links(url),
          sfh(url),
          check_email_submit(url),
          abnormal_url(url),
          redirect(url),
          on_mouse_over(url),
          right_click(url),
          pop_up(url),
          iframe(url),
          checK_age_domain(url),
          dns(url),
          web_traffic(url),
          page_run(url),
          google_index(url),
          link_pointing(url),
          statistical(url)
        ]]
    return check


# ,check_symbol_specification(url)



