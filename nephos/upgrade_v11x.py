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

from collections import namedtuple
import os

import click
from kubernetes.client.rest import ApiException

from nephos.fabric.crypto import CryptoInfo
from nephos.fabric.ord import check_ord
from nephos.fabric.peer import check_peer
from nephos.fabric.settings import get_namespace, load_config
from nephos.fabric.utils import get_pod
from nephos.helpers.helm import helm_upgrade
from nephos.helpers.k8s import secret_read, secret_create

PWD = os.getcwd()

NODE_MAPPER = {"orderer": "hlf-ord", "peer": "hlf-peer"}


# TODO: this module can be deleted once all our deployments are certain to have been migrated.
def extract_credentials(opts, node_type, verbose=False):
    chart = NODE_MAPPER[node_type]
    node_namespace = get_namespace(opts, opts[node_type + "s"]["msp"])
    # Loop over the nodes
    for release in opts[node_type + "s"]["names"]:
        secret_name = "hlf--{}-cred".format(release)
        try:
            secret_read(secret_name, node_namespace)
            if verbose:
                print("{} secret already exists".format(secret_name))
        except ApiException:
            # Obtain secret data from original chart secret
            original_data = secret_read("{}-{}".format(release, chart), node_namespace)
            # Create secret with Orderer credentials
            secret_data = {
                "CA_USERNAME": original_data["CA_USERNAME"],
                "CA_PASSWORD": original_data["CA_PASSWORD"],
            }
            secret_create(secret_data, secret_name, node_namespace, verbose=verbose)


def extract_crypto(opts, node_type, verbose=False):
    # Get chart type
    chart = NODE_MAPPER[node_type]
    node_namespace = get_namespace(opts, opts[node_type + "s"]["msp"])
    for release in opts[node_type + "s"]["names"]:
        pod_ex = get_pod(node_namespace, release, chart)
        # Secrets
        crypto_info = [
            CryptoInfo("idcert", "signcerts", "cert.pem", True),
            CryptoInfo("idkey", "keystore", "key.pem", True),
            CryptoInfo("cacert", "cacerts", "cacert.pem", True),
            CryptoInfo(
                "caintcert", "intermediatecerts", "intermediatecacert.pem", False
            ),
        ]
        for item in crypto_info:
            secret_name = "hlf--{}-{}".format(release, item.secret_type)
            try:
                secret_read(secret_name, node_namespace)
                if verbose:
                    print("{} secret already exists".format(secret_name))
            except ApiException:
                command = "bash -c 'ls /var/hyperledger/msp/{}' | wc -l".format(
                    item.subfolder
                )
                file_num, _ = pod_ex.execute(command)
                if file_num.strip() != "1":
                    if item.required:
                        raise ValueError(
                            "We should only have 1 file in each of these folders"
                        )
                    else:
                        print(
                            "Wrong number of files in {} directory".format(
                                item.subfolder
                            )
                        )
                else:
                    command = "bash -c 'cat /var/hyperledger/msp/{}/*'".format(
                        item.subfolder
                    )
                    content, _ = pod_ex.execute(command)
                    secret_data = {item.key: content}
                    secret_create(
                        secret_data, secret_name, node_namespace, verbose=verbose
                    )


def upgrade_charts(opts, node_type, verbose=False):
    # Get chart type
    chart = NODE_MAPPER[node_type]
    node_namespace = get_namespace(opts, opts[node_type + "s"]["msp"])
    for release in opts[node_type + "s"]["names"]:
        pod_ex = get_pod(node_namespace, release, chart)
        res, _ = pod_ex.execute("ls /var/hyperledger/msp_old")
        if not res:
            pod_ex.execute("mv /var/hyperledger/msp /var/hyperledger/msp_old")
        else:
            print("/var/hyperledger/msp_old already exists")
        config_yaml = "{dir}/{chart}/{name}.yaml".format(
            dir=opts["core"]["dir_values"], chart=chart, name=release
        )
        helm_upgrade(
            opts["core"]["chart_repo"],
            chart,
            release,
            node_namespace,
            config_yaml=config_yaml,
            verbose=verbose,
        )
        if node_type == "orderer":
            check_ord(node_namespace, release, verbose=verbose)
        elif node_type == "peer":
            check_peer(node_namespace, release, verbose=verbose)


@click.command()
@click.option(
    "--settings_file", "-f", required=True, help="YAML file containing HLF options"
)
@click.option("--verbose/--quiet", "-v/-q", default=False)
def main(settings_file, verbose=False):
    opts = load_config(settings_file)
    extract_credentials(opts, "orderer", verbose=verbose)
    extract_credentials(opts, "peer", verbose=verbose)
    extract_crypto(opts, "orderer", verbose=verbose)
    extract_crypto(opts, "peer", verbose=verbose)
    upgrade_charts(opts, "orderer", verbose=verbose)
    upgrade_charts(opts, "peer", verbose=verbose)


if __name__ == "__main__":  # pragma: no cover
    main()
