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

import random
from time import sleep

from nephos.fabric.settings import get_namespace
from nephos.fabric.utils import get_pod
from nephos.helpers.helm import HelmPreserve, helm_install, helm_upgrade
from nephos.helpers.misc import execute


# TODO: Move to Ord module
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
            "kubectl get cm -n {ns} "
            + '{release}-hlf-ord--ord -o jsonpath="{{.data.ORDERER_GENERAL_TLS_ENABLED}}"'
        ).format(ns=ord_namespace, release=opts["orderers"]["names"][0]),
        verbose=verbose,
    )
    return ord_tls == "true"


def check_peer(namespace, release, verbose=False):
    """Check if Peer is running.

    Args:
        namespace: Namespace where Peer is located.
        release: Name of Peer Helm release.
        verbose (bool): Verbosity. False by default.

    Returns:
        bool: True once Peer is correctly running.
    """
    pod_exec = get_pod(
        namespace=namespace, release=release, app="hlf-peer", verbose=verbose
    )
    res = pod_exec.logs(1000)
    if "Received block" in res:
        return True
    while True:
        if "Starting peer" in res or "Sleeping" in res:
            return True
        else:
            sleep(15)
            res = pod_exec.logs(1000)


# TODO: Split CouchDB creation from Peer creation
def setup_peer(opts, upgrade=False, verbose=False):
    """Setup Peer on K8S.

    Args:
        opts (dict): Nephos options dict.
        upgrade (bool): Do we upgrade the deployment? False by default.
        verbose (bool): Verbosity. False by default.
    """
    peer_namespace = get_namespace(opts, opts["peers"]["msp"])
    for release in opts["peers"]["names"]:
        # Deploy the CouchDB instances
        if not upgrade:
            helm_install(
                opts["core"]["chart_repo"],
                "hlf-couchdb",
                "cdb-{}".format(release),
                peer_namespace,
                config_yaml="{dir}/hlf-couchdb/cdb-{name}.yaml".format(
                    dir=opts["core"]["dir_values"], name=release
                ),
                verbose=verbose,
            )
        else:
            preserve = (HelmPreserve('cdb-{}-hlf-couchdb'.format(release), 'COUCHDB_USERNAME', 'couchdbUsername'),
                        HelmPreserve('cdb-{}-hlf-couchdb'.format(release), 'COUCHDB_PASSWORD', 'couchdbPassword'))
            helm_upgrade(opts['core']['chart_repo'], 'hlf-couchdb', 'cdb-{}'.format(release), peer_namespace,
                         config_yaml='{dir}/hlf-couchdb/cdb-{name}.yaml'.format(dir=opts['core']['dir_values'],
                                                                                name=release),
                         preserve=preserve,
                         verbose=verbose)

        # Deploy the HL-Peer charts
        if not upgrade:
            helm_install(
                opts["core"]["chart_repo"],
                "hlf-peer",
                release,
                peer_namespace,
                config_yaml="{dir}/hlf-peer/{name}.yaml".format(
                    dir=opts["core"]["dir_values"], name=release
                ),
                verbose=verbose,
            )
        else:
            helm_upgrade(
                opts["core"]["chart_repo"],
                "hlf-peer",
                release,
                peer_namespace,
                config_yaml="{dir}/hlf-peer/{name}.yaml".format(
                    dir=opts["core"]["dir_values"], name=release
                ),
                verbose=verbose,
            )

        check_peer(peer_namespace, release, verbose=verbose)


# TODO: Split channel creation from channel joining
def setup_channel(opts, verbose=False):
    """Setup Channel for Peer.

    Args:
        opts (dict): Nephos options dict.
        verbose (bool): Verbosity. False by default.
    """
    peer_namespace = get_namespace(opts, opts["peers"]["msp"])
    ord_namespace = get_namespace(opts, opts["orderers"]["msp"])
    # Get orderer TLS status
    ord_tls = check_ord_tls(opts, verbose=verbose)
    ord_name = random.choice(opts["orderers"]["names"])
    if ord_tls:
        cmd_suffix = (
            "--tls "
            + "--ordererTLSHostnameOverride {orderer}-hlf-ord "
            + "--cafile $(ls ${{ORD_TLS_PATH}}/*.pem)"
        ).format(orderer=ord_name)
    else:
        cmd_suffix = ""

    for index, release in enumerate(opts["peers"]["names"]):
        # Get peer pod
        pod_ex = get_pod(peer_namespace, release, "hlf-peer", verbose=verbose)

        # Check if the file exists
        has_channel = False
        while not has_channel:
            channel_block, _ = pod_ex.execute(
                "ls /var/hyperledger/{channel}.block".format(
                    channel=opts["peers"]["channel_name"]
                )
            )
            if not channel_block:
                if index == 0:
                    pod_ex.execute(
                        (
                            "bash -c 'peer channel create "
                            + "-o {orderer}-hlf-ord.{ns}.svc.cluster.local:7050 "
                            + "-c {channel} -f /hl_config/channel/{channel}.tx {cmd_suffix}'"
                        ).format(
                            orderer=ord_name,
                            ns=ord_namespace,
                            channel=opts["peers"]["channel_name"],
                            cmd_suffix=cmd_suffix,
                        )
                    )
                # TODO: This should have same ordering as above command
                pod_ex.execute(
                    (
                        "bash -c 'peer channel fetch 0 "
                        + "/var/hyperledger/{channel}.block "
                        + "-c {channel} "
                        + "-o {orderer}-hlf-ord.{ns}.svc.cluster.local:7050 {cmd_suffix}'"
                    ).format(
                        orderer=ord_name,
                        ns=ord_namespace,
                        channel=opts["peers"]["channel_name"],
                        cmd_suffix=cmd_suffix,
                    )
                )
            else:
                has_channel = True
        res, _ = pod_ex.execute("peer channel list")
        channels = (res.split("Channels peers has joined: ")[1]).split()
        if opts["peers"]["channel_name"] not in channels:
            pod_ex.execute(
                (
                    "bash -c "
                    + "'CORE_PEER_MSPCONFIGPATH=$ADMIN_MSP_PATH "
                    + "peer channel join -b /var/hyperledger/{channel}.block {cmd_suffix}'"
                ).format(channel=opts["peers"]["channel_name"], cmd_suffix=cmd_suffix)
            )
