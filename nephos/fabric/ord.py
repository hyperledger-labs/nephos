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

from nephos.fabric.utils import get_pod
from nephos.fabric.settings import get_namespace
from nephos.helpers.helm import helm_install, helm_upgrade


def check_ord(namespace, release, verbose=False):
    """Check if Orderer is running.

    Args:
        namespace (str): Namespace where Orderer is located.
        release (str): Name of Orderer Helm release.
        verbose (bool): Verbosity. False by default.

    Returns:
        bool: True once Orderer is correctly running.
    """
    pod_exec = get_pod(
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
        helm_install(
            "incubator",
            "kafka",
            "kafka-hlf",
            ord_namespace,
            config_yaml="{dir}/kafka/kafka-hlf.yaml".format(
                dir=opts["core"]["dir_values"]
            ),
            pod_num=opts["orderers"]["kafka"]["pod_num"],
            verbose=verbose,
        )

    for release in opts["orderers"]["names"]:
        # HL-Ord
        if not upgrade:
            helm_install(
                opts["core"]["chart_repo"],
                "hlf-ord",
                release,
                ord_namespace,
                config_yaml="{dir}/hlf-ord/{name}.yaml".format(
                    dir=opts["core"]["dir_values"], name=release
                ),
                verbose=verbose,
            )
        else:
            helm_upgrade(
                opts["core"]["chart_repo"],
                "hlf-ord",
                release,
                ord_namespace,
                config_yaml="{dir}/hlf-ord/{name}.yaml".format(
                    dir=opts["core"]["dir_values"], name=release
                ),
                verbose=verbose,
            )
        # Check that Orderer is running
        check_ord(ord_namespace, release, verbose=verbose)
