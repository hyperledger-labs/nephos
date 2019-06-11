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

import json

from nephos.fabric.settings import get_namespace

"""Connection template.

This module sets up a connection_json for Hyperledger Composer.
"""


# TODO: We need to improve this to be better organised, and use information from Kubernetes:
# TODO: Peer addresses should depend on whether we are using internal addresses only or using an ingress.
# TODO: Organisation name/subdomain should be a variable
# TODO: Ports should depend on whether internal/external addresses
# TODO: CA Host should be obtained via Kubernetes configuration
def define_orderers(orderer_names, orderer_hosts, domain=None):
    """Define orderers as connection objects.

        Args:
            orderer_names (Iterable): List of orderer names.
            orderer_hosts (Iterable): List of orderer hosts.
            domain (str): Domain used. Defaults to none.

        Returns:
            dict: A dictionary of Orderer Connections
    """
    orderer_connections = {}
    for name, host in zip(orderer_names, orderer_hosts):
        if domain:
            key = f"{name}.{domain}"
        else:
            key = name
        orderer_connections[key] = {"url": ("grpc://" + host + ":7050")}
    return orderer_connections


def define_peers(peer_names, peer_hosts, organisation, domain=None):
    """Define peers as connection objects.

        Args:
            peer_names (Iterable): List of peer names.
            peer_hosts (Iterable): List of peer hosts.
            organisation (str): What organisation the peers belong to
            domain (str): Domain used. Defaults to none.

        Returns:
            tuple: A tuple of dictionaries with Peer Options and Peer Connections.
    """
    peer_options = {}
    peer_connections = {}
    for name, host in zip(peer_names, peer_hosts):
        if domain:
            key = f"{name}.{organisation}.{domain}"
        else:
            key = name
        peer_options[key] = {
            "chaincodeQuery": True,
            "endorsingPeer": True,
            "eventSource": True,
            "ledgerQuery": True,
        }
        peer_connections[key] = {
            "url": ("grpc://" + host + ":7051"),
            "eventUrl": ("grpc://" + host + ":7053"),
        }
    return peer_options, peer_connections


def json_ct(opts, ca_name, ca_host, organisation, domain, msp_id, channel):
    """JSON connection template.

    Args:
        opts (dict): Nephos options dict.
        ca_name (str): Name of CA for Peers.
        ca_host (str): CA host address.
        organisation (str): What organisation the peers belong to.
        domain (str): Domain used.
        msp_id (str): ID of the MSP of the peers.
        channel (str): Channel name.

    Returns:
        dict: A dictionary representing the JSON connection template.
    """
    # Derive variables
    peer_namespace = get_namespace(opts, opts["peers"]["msp"])
    ord_namespace = get_namespace(opts, opts["orderers"]["msp"])
    # TODO: Currently specific to intra-cluster communication (Service)
    peer_hosts = [
        peer + f"-hlf-peer.{peer_namespace}.svc.cluster.local"
        for peer in opts["peers"]["names"]
    ]
    orderer_hosts = [
        orderer + f"-hlf-ord.{ord_namespace}.svc.cluster.local"
        for orderer in opts["orderers"]["names"]
    ]
    # Get peers
    peer_options, peer_connections = define_peers(
        opts["peers"]["names"], peer_hosts, organisation, domain
    )
    peer_names = [key for key, value in peer_options.items()]
    # Get orderers
    orderer_connections = define_orderers(
        opts["orderers"]["names"], orderer_hosts, domain
    )
    orderer_names = [key for key, value in orderer_connections.items()]
    return json.dumps(
        {
            "name": "hlfv1",
            "x-type": "hlfv1",
            "x-commitTimeout": 100,
            "version": "1.0.0",
            "client": {
                "organization": organisation,
                "connection": {
                    "timeout": {
                        "peer": {
                            "endorser": "300",
                            "eventHub": "300",
                            "eventReg": "300",
                        },
                        "orderer": "300",
                    }
                },
            },
            "channels": {channel: {"orderers": orderer_names, "peers": peer_options}},
            "organizations": {
                organisation: {
                    "mspid": msp_id,
                    "peers": peer_names,
                    "certificateAuthorities": [ca_name],
                }
            },
            "orderers": orderer_connections,
            "peers": peer_connections,
            "certificateAuthorities": {
                ca_name: {
                    "url": ("https://" + ca_host + ":443"),
                    "caName": ca_name,
                    # TODO: Ideally this should be set to True
                    "httpOptions": {"verify": False},
                }
            },
        }
    )
