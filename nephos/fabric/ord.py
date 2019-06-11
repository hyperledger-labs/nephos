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

from nephos.fabric.utils import get_helm_pod
from nephos.fabric.settings import get_namespace, get_version
from nephos.helpers.helm import helm_check, helm_extra_vars, helm_install, helm_upgrade
from nephos.helpers.misc import execute


def check_ord(namespace, release, verbose=False):
    """Check if Orderer is running.

    Args:
        namespace (str): Namespace where Orderer is located.
        release (str): Name of Orderer Helm release.
        verbose (bool): Verbosity. False by default.

    Returns:
        bool: True once Orderer is correctly running.
    """
    pod_exec = get_helm_pod(
        namespace=namespace, release=release, app="hlf-ord", verbose=verbose
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
def check_ord_tls(opts, verbose=False):
    """Check TLS status of Orderer.

    Args:
        opts (dict): Nephos options dict.
        verbose (bool): Verbosity. False by default.

    Returns:
        bool: True if TLS is enabled, False if TLS is disabled.
    """
    ord_namespace = get_namespace(opts, opts["orderers"]["msp"])
    ord_tls, _ = execute(
        (
            f"kubectl get cm -n {ord_namespace} "
            + f'{opts["orderers"]["names"][0]}-hlf-ord--ord -o jsonpath="{{.data.ORDERER_GENERAL_TLS_ENABLED}}"'
        ),
        verbose=verbose,
    )
    return ord_tls == "true"


def setup_ord(opts, upgrade=False, verbose=False):
    """Setup Orderer on K8S.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        verbose (bool): Verbosity. False by default.
    """
    ord_namespace = get_namespace(opts, opts["orderers"]["msp"])
    # Kafka
    if "kafka" in opts["orderers"]:
        # Kafka upgrade is risky, so we disallow it by default
        version = get_version(opts, "kafka")
        config_yaml = f"{opts['core']['dir_values']}/kafka/{opts['orderers']['kafka']['name']}.yaml"
        extra_vars = helm_extra_vars(version=version, config_yaml=config_yaml)
        helm_install(
            "incubator",
            "kafka",
            opts["orderers"]["kafka"]["name"],
            ord_namespace,
            extra_vars=extra_vars,
            verbose=verbose,
        )
        helm_check(
            "kafka",
            opts["orderers"]["kafka"]["name"],
            ord_namespace,
            pod_num=opts["orderers"]["kafka"]["pod_num"],
        )

    for release in opts["orderers"]["names"]:
        # HL-Ord
        version = get_version(opts, "hlf-ord")
        config_yaml = f'{opts["core"]["dir_values"]}/hlf-ord/{release}.yaml'
        extra_vars = helm_extra_vars(version=version, config_yaml=config_yaml)
        if not upgrade:
            helm_install(
                opts["core"]["chart_repo"],
                "hlf-ord",
                release,
                ord_namespace,
                extra_vars=extra_vars,
                verbose=verbose,
            )
        else:
            helm_upgrade(
                opts["core"]["chart_repo"],
                "hlf-ord",
                release,
                extra_vars=extra_vars,
                verbose=verbose,
            )
        helm_check("hlf-ord", release, ord_namespace)
        # Check that Orderer is running
        check_ord(ord_namespace, release, verbose=verbose)
