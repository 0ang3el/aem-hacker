#! /usr/bin/env python3
# vim: et:ts=4:sts=4:sw=4:fileencoding=utf-8
r"""
Crawl an Adobe Experience Manager site.

Usage:

    python3 {script} HOSTNAME [/PATH]
"""

import os
if os.name == "nt":
    # Check if executing the Windows build of Python from a Cygwin shell.
    if "TZ" in os.environ:
        # The Windows build of Python (as opposed to the Cygwin one) appears
        # confused with the TZ variable set by the Cygwin shell.  The former
        # sets time.timezone to 0, time.altzone to -3600 (-1 hr) in the
        # presence of TZ="America/New_York", which turns the local time zone to
        # UTC.
        del os.environ["TZ"]
import time
import calendar

import http.client
import json
import ssl


class Usage(SystemExit):
    def __init__(self, complaint=None):
        super(Usage, self).__init__(__doc__.format(script=os.path.basename(__file__))
                + ("" if complaint is None else "\nERROR: %s\n" % (complaint,)) )


def to_s_since_epoch(tsz=None):
    if tsz is None:
        # 2020-05-12T02:36:36-0400
        tsz = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    if tsz.endswith("Z"):
        tsz = tsz[:-1] + "-00:00"
    if tsz[-3] == ":":
        tsz = tsz[:-3] + tsz[-2:]
    utcfix = 0
    utcsign = "-"
    if tsz[-5] in ("-", "+"):
        utcfix = 60 * ((60 * int(tsz[-4:-2])) + int(tsz[-2]))
        utcsign = tsz[-5]
        if utcsign == "+":
            utcfix = -utcfix
        tsz = tsz[:-5]
    if tsz[-4] == ".":
        tsz = tsz[:-4]
    ts = time.strptime(tsz + " -00:00", "%Y-%m-%dT%H:%M:%S %z")
    s_since_epoch = calendar.timegm(ts) + utcfix
    return s_since_epoch


def local_timestamp(s_since_epoch=None):
    if s_since_epoch is None:
        # This assumes that localtime() knows both the UTC time in seconds
        # since epoch and the local current time zone.
        pass
    else:
        # This assumes that s_since_epoch reflects the UTC time in seconds
        # since epoch.  The local current time zone is needed to properly
        # change that.
        if s_since_epoch < 0:
            return "infinity"
        elif s_since_epoch == 0:
            return "olden times"
    t = time.localtime(s_since_epoch)
    is_dst = time.daylight and t.tm_isdst
    zone = time.altzone if is_dst else time.timezone
    strtime = time.strftime("%Y-%m-%d %H:%M:%S", t)
    utcoff = -zone
    if utcoff > 0:
        utcsign = "+"
    else:
        utcsign = "-"
        utcoff = -utcoff
    strtime += ("%s%02d%02d" % (utcsign, utcoff // 3600, (utcoff % 3600) // 60))
    return strtime


def slurp(conn, site, uri):
    conn.request("GET", uri)
    try:
        r = conn.getresponse()
    except (http.client.RemoteDisconnected, http.client.ResponseNotReady):
        print(f"Reconnecting to {site}...", flush=True)
        conn = http.client.HTTPSConnection(site, context=ssl._create_unverified_context())
        conn.request("GET", uri)
        r = conn.getresponse()
    # print(r.status, r.reason, flush=True)
    # if r.status != http.HTTPStatus.OK:
    #     return None, conn
    data = r.read()
    headerslc = dict((k.lower(), v) for (k, v) in r.getheaders())
    ct = headerslc.get("content-type")
    if ct is not None:
        ct = ct.split(";")[0]
        if ct == "application/json":
            if len(data) == 0:
                data = []
            else:
                data = json.loads(data)
        elif ct.split("/")[0] == "text":
            data = data.decode("utf-8", "replace")
    return data, conn


def start_dig(site, path=None):
    print(f"Connecting to {site}...", flush=True)
    conn = http.client.HTTPSConnection(site, context=ssl._create_unverified_context())
    visited = {}

    def dig(path, level=0):
        nonlocal conn, site, visited
        if path is None:
            path = ""
        children, conn = slurp(conn, site, path + "/.children.json")
        for child in children:
            if "uri" in child:
                tsz = child.get("jcr:created", "2000-01-01T00:00:00Z")
                s_since_epoch = to_s_since_epoch(tsz)
                tsstr = local_timestamp(s_since_epoch)
                created_by = child.get("jcr:createdBy", "UNKNOWN")
                uri = child["uri"]
                if uri not in visited:
                    pt = child.get("jcr:primaryType")
                    if pt == "cq:Page":
                        dig(uri, level + 1)
                    elif pt == "cq:PageContent":
                        htmluri = uri
                        if htmluri.endswith("/jcr:content"):
                            htmluri = htmluri[:-len("/jcr:content")] + ".html"
                        html, conn = slurp(conn, site, htmluri)
                        child["FETCHED_HTML"] = html
                    print(tsstr, uri, created_by, json.dumps(child), flush=True)
                    visited[uri] = (tsstr, created_by)
    dig(path)


def main(site=None, *args):
    if site is None:
        raise Usage()
    path = None
    if len(args) > 0:
        path = args[0]
    start_dig(site, path)


if __name__ == "__main__":
    import sys
    main(*sys.argv[1:])

