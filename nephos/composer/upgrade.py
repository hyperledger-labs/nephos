#! /usr/bin/env python

import os

from nephos.fabric.settings import get_namespace
from nephos.fabric.utils import get_pod
from nephos.helpers.k8s import secret_from_file

CURRENT_DIR = os.path.abspath(os.path.split(__file__)[0])


def upgrade_network(opts, verbose=False):
    peer_namespace = get_namespace(opts, opts["peers"]["msp"])
    secret_from_file(
        secret=opts["composer"]["secret_bna"], namespace=peer_namespace, verbose=verbose
    )
    # Set up the PeerAdmin card
    hlc_cli_ex = get_pod(peer_namespace, "hlc", "hl-composer", verbose=verbose)

    bna, _ = hlc_cli_ex.execute("ls /hl_config/blockchain_network")
    bna_name, bna_rem = bna.split("_")
    bna_version, _ = bna_rem.split(".bna")
    peer_msp = opts["peers"]["msp"]
    peer_ca = opts["msps"][peer_msp]["ca"]
    bna_admin = opts["msps"][peer_msp]["org_admin"]

    res, _ = hlc_cli_ex.execute(
        "composer network ping --card {bna_admin}@{bna_name}".format(
            bna_admin=bna_admin, bna_name=bna_name
        )
    )

    curr_version = (res.split("Business network version: ")[1]).split()[0]
    print(curr_version)

    if curr_version != bna_version:
        hlc_cli_ex.execute(
            (
                "composer network install --card PeerAdmin@hlfv1 "
                + "--archiveFile /hl_config/blockchain_network/{bna}"
            ).format(bna=bna)
        )
        hlc_cli_ex.execute(
            (
                "composer network upgrade "
                + "--card PeerAdmin@hlfv1 "
                + "--networkName {bna_name} --networkVersion {bna_version}"
            ).format(bna_name=bna_name, bna_version=bna_version)
        )
        res, _ = hlc_cli_ex.execute(
            "composer network ping --card {bna_admin}@{bna_name}".format(
                bna_admin=bna_admin, bna_name=bna_name
            )
        )
        curr_version = (res.split("Business network version: ")[1]).split()[0]
        print("Upgraded to {version}".format(version=curr_version))
