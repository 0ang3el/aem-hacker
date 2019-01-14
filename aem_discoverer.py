import itertools
import concurrent.futures
import sys
import json
import datetime
import traceback
import argparse
from threading import Lock, Semaphore

import requests

requests.packages.urllib3.disable_warnings()

registered = []
lock = Lock()
semaphore = None


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


def register(f):
    registered.append(f)

    return f


def normalize_url(base_url, path):
    if base_url[-1] == '/' and (path[0] == '/' or path[0] == '\\'):
        url = base_url[:-1] + path
    else:
        url = base_url + path

    return url


def http_request(url, method='GET', data=None, additional_headers=None, proxy=None):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0'}
    if additional_headers:
        headers.update(additional_headers)

    if not proxy:
        proxy = {}

    resp = requests.request(method, url, data=data, headers=headers, proxies=proxy, verify=False, timeout=15, allow_redirects=False)

    return resp


def preflight(url, proxy=None):
    try:
        http_request(url, proxy=proxy)
    except:
        return False
    else:
        return True


def content_type(ct):
    return ct.split(';')[0].lower().strip()


@register
def by_login_page(base_url, debug, proxy=None):
    LOGIN_PAGE = '/libs/granite/core/content/login.html'
    url = normalize_url(base_url, LOGIN_PAGE)

    try:
        resp = http_request(url, proxy=proxy)

        if resp.status_code == 200 and 'Welcome to Adobe Experience Manager' in resp.content:
            return True
    except:
        if debug:
            error('Exception', method='by_login_page', url=url)


@register
def by_geometrixx_page(base_url, debug, proxy=None):
    GEOMETRIXX = '/content/geometrixx/en.html'
    url = normalize_url(base_url, GEOMETRIXX)

    try:
        resp = http_request(url, proxy=proxy)

        if resp.status_code == 200 and 'Geometrixx has been selling' in resp.content:
            return True
    except:
        if debug:
            error('Exception', method='by_geometrixx_page', url=url)


@register
def by_get_servlet(base_url, debug, proxy=None):
    GETSERVLET = itertools.product(('/', '/content', '/content/dam', '/bin', '///bin'),
                                   ('.json', '.1.json', '.childrenlist.json', '.ext.json', '.4.2.1...json', '.json/a.css',
                                    '.json/a.html', '.json/a.png', '.json/a.ico', '.json;%0aa.css', '.json;%0aa.html',
                                    '.json;%0aa.png', '.json;%0aa.ico'))
    GETSERVLET = list('{0}{1}'.format(p1, p2) for p1, p2 in GETSERVLET)

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
                    return True

                try:
                    json.loads(resp.content.decode())['parent']['resourceType']
                except:
                    pass
                else:
                    return True

                try:
                    json.loads(resp.content.decode())[0]['type']
                except:
                    pass
                else:
                    return True

        except:
            if debug:
                error('Exception', method='by_get_servlet', url=url)

    return False


@register
def by_bin_receive(base_url, debug, proxy=None):
    BINRECEIVE = itertools.product(('/bin/receive{0}?sling:authRequestLogin=1', '/bin/receive.servlet{0}?sling:authRequestLogin=1'),
                                   ('.css', '.html', '.js', '.ico', '.png', '.gif', '.1.json', '.4.2.1...json'))
    BINRECEIVE = list(p1.format(p2) for p1, p2 in BINRECEIVE)

    for path in BINRECEIVE:
        url = normalize_url(base_url, path)

        try:
            resp = http_request(url, proxy=proxy)

            header = resp.headers.get('WWW-Authenticate', '').lower()
            if resp.status_code == 401 and ('day' in header or 'sling' in header or 'aem' in header or 'communique' in header or 'adobe' in header):
                return True
        except:
            if debug:
                error('Exception', method='by_bin_receive', url=url)

    return False


@register
def by_loginstatus_servlet(base_url, debug, proxy=None):
    LOGINSTATUS = itertools.product(('/system/sling/loginstatus', '///system///sling///loginstatus'),
                                    ('.json', '.css', '.png', '.gif', '.html', '.ico', '.json/a.1.json',
                                     '.json;%0aa.css', '.json;%0aa.html', '.json;%0aa.ico'))
    LOGINSTATUS = list('{0}{1}'.format(p1, p2) for p1, p2 in LOGINSTATUS)

    for path in LOGINSTATUS:
        url = normalize_url(base_url, path)

        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200 and 'authenticated=' in resp.content:
                return True
        except:
            if debug:
                error('Exception', method='by_loginstatus_servlet', url=url)

    return False


@register
def by_bgtest_servlet(base_url, debug, proxy=None):
    TESTSERVLET = itertools.product(('/system/bgservlets/test', '///system///bgservlets///test'),
                                    ('.json', '.css', '.png', 'ico', '.gif', '.html', '.json/a.1.json', '.json;%0aa.css',
                                    '.json;%0aa.html', '.json;%0aa.ico'))
    TESTSERVLET = list('{0}{1}'.format(p1, p2) for p1, p2 in TESTSERVLET)

    for path in TESTSERVLET:
        url = normalize_url(base_url, path)

        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200 and 'All done.' in resp.content and 'Cycle' in resp.content:
                return True
        except:
            if debug:
                error('Exception', method='by_bgtest_servlet', url=url)

    return False


@register
def by_crx(base_url, debug, proxy=None):
    CRX = itertools.product(('/crx/de/index.jsp', '/crx/explorer/browser/index.jsp', '/crx/packmgr/index.jsp'),
                            ('', ';%0aa.css', ';%0aa.html', ';%0aa.ico', ';%0aa.png', '?a.css', '?a.html', '?a.png', '?a.ico'))
    CRX = list('{0}{1}'.format(p1, p2) for p1, p2 in CRX)

    for path in CRX:
        url = normalize_url(base_url, path)

        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200 and ('CRXDE Lite' in resp.content or 'Content Explorer' in resp.content or
                                            'CRX Package Manager' in resp.content):
                return True
        except:
            if debug:
                error('Exception', method='by_crx', url=url)

    return False


@register
def by_gql_servlet(base_url, debug, proxy=None):
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
                    return True
        except:
            if debug:
                error('Exception', method='by_gql_servlet', url=url)

    return False


@register
def by_swf(base_url, debug, proxy=None):
    SWFS = (
        '/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf',
        '/etc/clientlibs/foundation/video/swf/player_flv_maxi.swf.res',
        '/etc/clientlibs/foundation/shared/endorsed/swf/slideshow.swf',
        '/etc/clientlibs/foundation/shared/endorsed/swf/slideshow.swf.res',
        '/etc/clientlibs/foundation/video/swf/StrobeMediaPlayback.swf',
        '/etc/clientlibs/foundation/video/swf/StrobeMediaPlayback.swf.res',
        '/libs/dam/widgets/resources/swfupload/swfupload_f9.swf',
        '/libs/dam/widgets/resources/swfupload/swfupload_f9.swf.res',
        '/libs/cq/ui/resources/swfupload/swfupload.swf',
        '/libs/cq/ui/resources/swfupload/swfupload.swf.res',
        '/etc/dam/viewers/s7sdk/2.11/flash/VideoPlayer.swf',
        '/etc/dam/viewers/s7sdk/2.11/flash/VideoPlayer.swf.res',
        '/etc/dam/viewers/s7sdk/2.9/flash/VideoPlayer.swf',
        '/etc/dam/viewers/s7sdk/2.9/flash/VideoPlayer.swf.res',
        '/etc/dam/viewers/s7sdk/3.2/flash/VideoPlayer.swf',
        '/etc/dam/viewers/s7sdk/3.2/flash/VideoPlayer.swf.res'
    )

    for path in SWFS:
        url = normalize_url(base_url, path)

        try:
            resp = http_request(url, proxy=proxy)

            ct = content_type(resp.headers.get('Content-Type', ''))
            if resp.status_code == 200 and ct == 'application/x-shockwave-flash':
                return True
        except:
            if debug:
                error('Exception', method='by_swf', url=url)

    return False


def check_url(base_url, debug, proxy=None):
    if not preflight(base_url, proxy):
        return

    if any(method(base_url, debug, proxy) for method in registered):
        return base_url


def handle_finding(future):
    global semaphore, lock

    semaphore.release()

    if future.done():
        if not future.exception():
            result = future.result()

            with lock:
                if result:
                    print(result)


def parse_args():
    parser = argparse.ArgumentParser(description='AEM discoverer by @0ang3el, see the slides - https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps')

    parser.add_argument('--file', help='file with urls')
    parser.add_argument('--proxy', help='http and https proxy')
    parser.add_argument('--debug', action='store_true', help='debug output')
    parser.add_argument('--workers', type=int, default=50, help='number of parallel workers')

    return parser.parse_args(sys.argv[1:])


def main():
    global semaphore

    args = parse_args()

    if args.proxy:
        p = args.proxy
        proxy = {'http': p, 'https': p}
    else:
        proxy = {}

    if not args.file:
        print('You must specify the --file parameter, bye.')
        sys.exit(1337)

    semaphore = Semaphore(args.workers)

    with concurrent.futures.ThreadPoolExecutor(args.workers) as tpe, open(args.file, 'r') as input:
        while True:
            line = input.readline()
            if not line:
                break

            url = line.strip()

            semaphore.acquire()
            try:
                future = tpe.submit(check_url, url, args.debug, proxy)
                future.add_done_callback(handle_finding)
            except:
                semaphore.release()

        tpe.shutdown(wait=True)


if __name__ == '__main__':
    main()