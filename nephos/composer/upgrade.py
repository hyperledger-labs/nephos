#! /usr/bin/env python

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

import os
import logging

from nephos.fabric.settings import get_namespace
from nephos.fabric.utils import get_helm_pod
from nephos.helpers.k8s import secret_from_file

CURRENT_DIR = os.path.abspath(os.path.split(__file__)[0])


def upgrade_network(opts, verbose=False):
    """Upgrade Hyperledger Composer network.

    Args:
        opts (dict): Nephos options dict.
        verbose (bool): Verbosity. False by default.
    """
    peer_namespace = get_namespace(opts, opts["peers"]["msp"])
    secret_from_file(
        secret=opts["composer"]["secret_bna"], namespace=peer_namespace, verbose=verbose
    )
    # Set up the PeerAdmin card
    hlc_cli_ex = get_helm_pod(peer_namespace, "hlc", "hl-composer", verbose=verbose)

    bna, _ = hlc_cli_ex.execute("ls /hl_config/blockchain_network")
    bna_name, bna_rem = bna.split("_")
    bna_version, _ = bna_rem.split(".bna")
    peer_msp = opts["peers"]["msp"]
    bna_admin = opts["msps"][peer_msp]["org_admin"]

    res, _ = hlc_cli_ex.execute(
        f"composer network ping --card {bna_admin}@{bna_name}"
    )

    curr_version = (res.split("Business network version: ")[1]).split()[0]
    logging.info(curr_version)

    if curr_version != bna_version:
        hlc_cli_ex.execute(
            (
                "composer network install --card PeerAdmin@hlfv1 "
                + f"--archiveFile /hl_config/blockchain_network/{bna}"
            )
        )
        hlc_cli_ex.execute(
            (
                "composer network upgrade "
                + "--card PeerAdmin@hlfv1 "
                + f"--networkName {bna_name} --networkVersion {bna_version}"
            )
        )
        res, _ = hlc_cli_ex.execute(
            f"composer network ping --card {bna_admin}@{bna_name}"
        )
        curr_version = (res.split("Business network version: ")[1]).split()[0]
        logging.info(f"Upgraded to {curr_version}")
