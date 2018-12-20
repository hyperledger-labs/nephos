#! /usr/bin/env python

import os

import click

from nephos.fabric.settings import load_config
from nephos.fabric.utils import get_pod
from nephos.helpers.k8s import ns_create

CURRENT_DIR = os.path.abspath(os.path.split(__file__)[0])


def upgrade_network(opts, verbose=False):
    # Set up the PeerAdmin card
    hlc_cli_ex = get_pod(opts['core']['namespace'], 'hlc', 'hl-composer', verbose=verbose)

    bna = hlc_cli_ex.execute('ls /hl_config/blockchain_network')
    bna_name, bna_rem = bna.split('_')
    bna_version, _ = bna_rem.split('.bna')
    peer_ca = opts['peers']['ca']
    bna_admin = opts['cas'][peer_ca]['org-admin']

    res = hlc_cli_ex.execute('composer network ping --card {bna_admin}@{bna_name}'.format(
        bna_admin=bna_admin, bna_name=bna_name))

    curr_version = (res.split('Business network version: ')[1]).split()[0]
    print(curr_version)

    if curr_version != bna_version:
        hlc_cli_ex.execute(
            ('composer network install --card PeerAdmin@hlfv1 ' +
             '--archiveFile /hl_config/blockchain_network/{bna}').format(bna=bna))
        hlc_cli_ex.execute(
            ('composer network upgrade ' +
             '--card PeerAdmin@hlfv1 ' +
             '--networkName {bna_name} --networkVersion {bna_version}').format(
                bna_name=bna_name, bna_version=bna_version
            ))


# TODO: Refactor and move to core click
@click.command()
@click.option('--settings_file', '-f', required=True, help='YAML file containing HLF options')
@click.option('--verbose/--quiet', '-v/-q', default=False)
def main(settings_file, verbose=False):  # pragma: no cover
    opts = load_config(settings_file)
    ns_create(opts['core']['namespace'], verbose=verbose)
    upgrade_network(opts, verbose=verbose)


if __name__ == "__main__":  # pragma: no cover
    main()
