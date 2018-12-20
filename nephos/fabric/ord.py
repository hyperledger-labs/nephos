from time import sleep

from nephos.fabric.utils import get_pod
from nephos.helpers.helm import helm_install, helm_upgrade


def check_ord(namespace, release, verbose=False):
    pod_exec = get_pod(namespace=namespace, release=release, app='hlf-ord', verbose=verbose)
    res = pod_exec.logs(1000)
    if 'fetching metadata for all topics from broker' in res:
        return True
    while True:
        if 'Starting orderer' in res:
            return True
        else:
            sleep(15)
            res = pod_exec.logs(1000)


def setup_ord(opts, upgrade=False, verbose=False):
    # Kafka
    if 'kafka' in opts['orderers']:
        # Kafka upgrade is risky, so we disallow it by default
        helm_install('incubator', 'kafka', 'kafka-hlf', opts['core']['namespace'],
                     config_yaml='{dir}/kafka/kafka-hlf.yaml'.format(dir=opts['core']['dir_values']),
                     pod_num=opts['orderers']['kafka']['pod_num'],
                     verbose=verbose)

    for release in opts['orderers']['names']:
        # HL-Ord
        if not upgrade:
            helm_install(opts['core']['chart_repo'], 'hlf-ord', release, opts['core']['namespace'],
                         config_yaml='{dir}/hlf-ord/{name}.yaml'.format(dir=opts['core']['dir_values'], name=release),
                         verbose=verbose)
        else:
            helm_upgrade(opts['core']['chart_repo'], 'hlf-ord', release, opts['core']['namespace'],
                         config_yaml='{dir}/hlf-ord/{name}.yaml'.format(dir=opts['core']['dir_values'], name=release),
                         verbose=verbose)
        # Check that Orderer is running
        check_ord(opts['core']['namespace'], release, verbose=verbose)
