import random
from time import sleep

from nephos.fabric.utils import get_pod
from nephos.helpers.helm import helm_install, helm_upgrade
from nephos.helpers.misc import execute


# TODO: Perhaps replace opts with orderer name
# TODO: Move to Ord module
# TODO: We need a similar check to see if Peer uses client TLS as well
def check_ord_tls(opts, verbose=False):
    ord_tls = execute(('kubectl get cm -n blockchain ' +
                       '{release}-hlf-ord--ord -o jsonpath="{{.data.ORDERER_GENERAL_TLS_ENABLED}}"'
                       ).format(release=opts['orderers']['names'][0]),
                      verbose=verbose)
    return ord_tls == 'true'


def check_peer(namespace, release, verbose=False):
    pod_exec = get_pod(namespace=namespace, release=release, app='hlf-peer', verbose=verbose)
    res = pod_exec.logs(1000)
    if 'Received block' in res:
        return True
    while True:
        if 'Starting peer' in res or 'Sleeping' in res:
            return True
        else:
            sleep(15)
            res = pod_exec.logs(1000)


# TODO: Split CouchDB creation from Peer creation
def setup_peer(opts, upgrade=False, verbose=False):
    for release in opts['peers']['names']:
        # Deploy the CouchDB instances
        if not upgrade:
            helm_install(opts['core']['chart_repo'], 'hlf-couchdb', 'cdb-{}'.format(release), opts['core']['namespace'],
                         config_yaml='{dir}/hlf-couchdb/cdb-{name}.yaml'.format(dir=opts['core']['dir_values'], name=release),
                         verbose=verbose)
        else:
            # We will not upgrade the CouchDB here, only explicitly in a separate script.
            pass
            # preserve = (HelmPreserve('cdb-{}-hlf-couchdb'.format(release), 'COUCHDB_USERNAME', 'couchdbUsername'),
            #             HelmPreserve('cdb-{}-hlf-couchdb'.format(release), 'COUCHDB_PASSWORD', 'couchdbPassword'))
            # helm_upgrade(opts['core']['chart_repo'], 'hlf-couchdb', 'cdb-{}'.format(release), opts['core']['namespace'],
            #              config_yaml='{dir}/hlf-couchdb/cdb-{name}.yaml'.format(dir=opts['core']['dir_values'],
            #                                                                     name=release),
            #              preserve=preserve,
            #              verbose=verbose)

        # Deploy the HL-Peer charts
        if not upgrade:
            helm_install(opts['core']['chart_repo'], 'hlf-peer', release, opts['core']['namespace'],
                         config_yaml='{dir}/hlf-peer/{name}.yaml'.format(dir=opts['core']['dir_values'], name=release),
                         verbose=verbose)
        else:
            helm_upgrade(opts['core']['chart_repo'], 'hlf-peer', release, opts['core']['namespace'],
                         config_yaml='{dir}/hlf-peer/{name}.yaml'.format(dir=opts['core']['dir_values'], name=release),
                         verbose=verbose)

        check_peer(opts['core']['namespace'], release, verbose=verbose)


# TODO: Split channel creation from channel joining
def setup_channel(opts, verbose=False):
    # Get orderer TLS status
    ord_tls = check_ord_tls(opts, verbose=verbose)
    ord_name = random.choice(opts['orderers']['names'])
    if ord_tls:
        cmd_suffix = ('--tls ' +
                      '--ordererTLSHostnameOverride {orderer}-hlf-ord ' +
                      '--cafile $(ls ${{ORD_TLS_PATH}}/*.pem)').format(orderer=ord_name)
    else:
        cmd_suffix = ''

    for index, release in enumerate(opts['peers']['names']):
        # Get peer pod
        pod_ex = get_pod(opts['core']['namespace'], release, 'hlf-peer', verbose=verbose)

        # Check if the file exists
        has_channel = False
        while not has_channel:
            channel_block = pod_ex.execute('ls /var/hyperledger/{channel}.block'.format(
                channel=opts['peers']['channel_name']))
            if not channel_block:
                if index == 0:
                    pod_ex.execute(
                        ("bash -c 'peer channel create " +
                         "-o {orderer}-hlf-ord.{ns}.svc.cluster.local:7050 " +
                         "-c {channel} -f /hl_config/channel/{channel}.tx {cmd_suffix}'").format(
                            orderer=ord_name,
                            ns=opts['core']['namespace'],
                            channel=opts['peers']['channel_name'],
                            cmd_suffix=cmd_suffix))
                # TODO: This should have same ordering as above command
                pod_ex.execute(
                    ("bash -c 'peer channel fetch 0 " +
                     "/var/hyperledger/{channel}.block " +
                     "-c {channel} " +
                     "-o {orderer}-hlf-ord.{ns}.svc.cluster.local:7050 {cmd_suffix}'").format(
                        orderer=ord_name,
                        ns=opts['core']['namespace'],
                        channel=opts['peers']['channel_name'],
                        cmd_suffix=cmd_suffix))
            else:
                has_channel = True
        res = pod_ex.execute('peer channel list')
        channels = (res.split('Channels peers has joined: ')[1]).split()
        if opts['peers']['channel_name'] not in channels:
            pod_ex.execute(
                ("bash -c " +
                 "'CORE_PEER_MSPCONFIGPATH=$ADMIN_MSP_PATH " +
                 "peer channel join -b /var/hyperledger/{channel}.block {cmd_suffix}'").format(
                    channel=opts['peers']['channel_name'],
                    cmd_suffix=cmd_suffix
                ))
