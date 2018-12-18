import json


# TODO: We need to improve this to be better organised, and use information from Kubernetes:
# i.e.
# 1) Peer addresses should depend on whether we are using internal addresses only or using an ingress.
# 2) Organisation name/subdomain should be a variable
# 3) Ports should depend on whether internal/external addresses
# 4) CA Host should be obtained via Kubernetes configuration
def define_orderers(orderer_names, orderer_hosts, domain=None):
    orderer_connections = {}
    for name, host in zip(orderer_names, orderer_hosts):
        if domain:
            key = "{name}.{domain}".format(
                name=name, domain=domain
            )
        else:
            key = name
        orderer_connections[key] = {
                "url": ("grpc://" + host + ":7050")
            }
    return orderer_connections


def define_peers(peer_names, peer_hosts, organisation, domain=None):
    peer_options = {}
    peer_connections = {}
    for name, host in zip(peer_names, peer_hosts):
        if domain:
            key = "{name}.{organisation}.{domain}".format(
                name=name, organisation=organisation, domain=domain
            )
        else:
            key = name
        peer_options[key] = {
                "chaincodeQuery": True,
                "endorsingPeer": True,
                "eventSource": True,
                "ledgerQuery": True
            }
        peer_connections[key] = {
            "url": ("grpc://" + host + ":7051"),
            "eventUrl": ("grpc://" + host + ":7053")
        }
    return peer_options, peer_connections


def json_ct(peer_names, orderer_names, peer_hosts, orderer_hosts,
            ca_name, ca_host, organisation, domain, msp_id, channel):
    # Get peers
    peer_options, peer_connections = define_peers(peer_names, peer_hosts, organisation, domain)
    peer_names = [key for key, value in peer_options.items()]
    # Get orderers
    orderer_connections = define_orderers(orderer_names, orderer_hosts, domain)
    orderer_names = [key for key, value in orderer_connections.items()]
    return json.dumps({
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
                        "eventReg": "300"
                    },
                    "orderer": "300"
                }
            }
        },
        "channels": {
            (channel): {
                "orderers": orderer_names,
                "peers": peer_options
            }
        },
        "organizations": {
            (organisation): {
                "mspid": msp_id,
                "peers": peer_names,
                "certificateAuthorities": [
                    (ca_name)
                ]
            }
        },
        "orderers": orderer_connections,
        "peers": peer_connections,
        "certificateAuthorities": {
            (ca_name): {
                "url": ("https://" + ca_host + ":443"),
                "caName": (ca_name),
                # TODO: Ideally this should be set to True
                "httpOptions": {
                    "verify": False
                }
            }
        }
    })
