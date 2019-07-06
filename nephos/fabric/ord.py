#   Copyright [2018] [Alejandro Vicente Grabovetsky via AID:Tech]
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at#
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from time import sleep

from nephos.fabric.utils import get_helm_pod, get_orderers, get_kafka_configs, get_msps, is_orderer_msp
from nephos.fabric.settings import get_namespace, get_version
from nephos.helpers.helm import helm_check, helm_extra_vars, helm_install, helm_upgrade
from nephos.helpers.misc import execute


def check_ord(namespace, release):
    """Check if Orderer is running.

    Args:
        namespace (str): Namespace where Orderer is located.
        release (str): Name of Orderer Helm release.

    Returns:
        bool: True once Orderer is correctly running.
    """
    pod_exec = get_helm_pod(
        namespace=namespace, release=release, app="hlf-ord"
    )
    res = pod_exec.logs(1000)
    if "fetching metadata for all topics from broker" in res:
        return True
    while True:
        if "Starting orderer" in res:
            return True
        else:
            sleep(15)
            res = pod_exec.logs(1000)


# TODO: We need a similar check to see if Peer uses client TLS as well
def check_ord_tls(opts, ord_msp, ord_name):
    """Check TLS status of Orderer.

    Args:
        opts (dict): Nephos options dict.
        ord_msp (str): orderer msp of the orderer we wish to check the tls
        ord_name (str): orderer name we wish to check the tls
    Returns:
        bool: True if TLS is enabled, False if TLS is disabled.
    """
    ord_namespace = get_namespace(opts, msp=ord_msp)
    ord_tls, _ = execute(
        (
            f"kubectl get cm -n {ord_namespace} "
            + f'{ord_name}-hlf-ord--ord -o jsonpath="{{.data.ORDERER_GENERAL_TLS_ENABLED}}"'
        ),
    )
    return ord_tls == "true"


def setup_ord(opts, upgrade=False):
    """Setup Orderer on K8S.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
    """
    # Kafka
    if "kafka" in opts["ordering"]:
        # Kafka upgrade is risky, so we disallow it by default
        version = get_version(opts, "kafka")
        kafka_config = get_kafka_configs(opts=opts)
        ord_namespace = get_namespace(opts, msp=kafka_config["msp"])
        config_yaml = f"{opts['core']['dir_values']}/{kafka_config['msp']}/kafka/{kafka_config['name']}.yaml"
        extra_vars = helm_extra_vars(version=version, config_yaml=config_yaml)
        helm_install(
            "incubator",
            "kafka",
            kafka_config['name'],
            ord_namespace,
            extra_vars=extra_vars,
        )
        helm_check(
            "kafka",
            kafka_config['name'],
            ord_namespace,
            pod_num=kafka_config["pod_num"],
        )

    for msp in get_msps(opts=opts):
        if not is_orderer_msp(opts=opts, msp=msp):
            continue
        ord_namespace = get_namespace(opts, msp=msp)
        version = get_version(opts, "hlf-ord")
        for release in get_orderers(opts=opts, msp=msp):
            # HL-Ord
            config_yaml = f'{opts["core"]["dir_values"]}/{msp}/hlf-ord/{release}.yaml'
            extra_vars = helm_extra_vars(version=version, config_yaml=config_yaml)
            if not upgrade:
                helm_install(
                    opts["core"]["chart_repo"],
                    "hlf-ord",
                    release,
                    ord_namespace,
                    extra_vars=extra_vars,
                )
            else:
                helm_upgrade(
                    opts["core"]["chart_repo"],
                    "hlf-ord",
                    release,
                    extra_vars=extra_vars,
                )
            helm_check("hlf-ord", release, ord_namespace)
            # Check that Orderer is running
            check_ord(ord_namespace, release)
