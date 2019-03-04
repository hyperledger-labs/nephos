from unittest.mock import patch

from nephos.composer.connection_template import define_orderers, define_peers, json_ct


class TestDefineOrderers:
    def test_define_orderers(self):
        res = define_orderers(
            ["ord0", "ord1"], ["ord0.local-cluster", "ord1.local-cluster"]
        )
        assert res == {
            "ord0": {"url": "grpc://ord0.local-cluster:7050"},
            "ord1": {"url": "grpc://ord1.local-cluster:7050"},
        }

    def test_define_orderers_domain(self):
        res = define_orderers(
            ["ord0", "ord1"],
            ["ord0.local-cluster", "ord1.local-cluster"],
            domain="a-domain.com",
        )
        assert res == {
            "ord0.a-domain.com": {"url": "grpc://ord0.local-cluster:7050"},
            "ord1.a-domain.com": {"url": "grpc://ord1.local-cluster:7050"},
        }


class TestDefinePeers:
    def test_define_peers(self):
        res = define_peers(["peer0"], ["peer0.local-cluster"], "an-org")
        assert res == (
            {
                "peer0": {
                    "chaincodeQuery": True,
                    "endorsingPeer": True,
                    "eventSource": True,
                    "ledgerQuery": True,
                }
            },
            {
                "peer0": {
                    "url": "grpc://peer0.local-cluster:7051",
                    "eventUrl": "grpc://peer0.local-cluster:7053",
                }
            },
        )

    def test_define_peers_domain(self):
        res = define_peers(
            ["peer0"], ["peer0.local-cluster"], "an-org", domain="a-domain.com"
        )
        assert res == (
            {
                "peer0.an-org.a-domain.com": {
                    "chaincodeQuery": True,
                    "endorsingPeer": True,
                    "eventSource": True,
                    "ledgerQuery": True,
                }
            },
            {
                "peer0.an-org.a-domain.com": {
                    "url": "grpc://peer0.local-cluster:7051",
                    "eventUrl": "grpc://peer0.local-cluster:7053",
                }
            },
        )


# TODO: This command is much too complicated (simplify and derive from hlf_config.yaml
class TestJsonCt:
    OPTS = {
        "msps": {
            "ord_MSP": {"namespace": "ord-namespace"},
            "peer_MSP": {"namespace": "peer-namespace"},
        },
        "orderers": {"msp": "ord_MSP", "names": ["ord0"]},
        "peers": {"msp": "peer_MSP", "names": ["peer0"]},
    }

    @patch("nephos.composer.connection_template.define_peers")
    @patch("nephos.composer.connection_template.define_orderers")
    def test_json_ct(self, mock_define_orderers, mock_define_peers):
        mock_define_peers.side_effect = [
            (
                {
                    "peer0.an-org.a-domain.com": {
                        "chaincodeQuery": True,
                        "endorsingPeer": True,
                        "eventSource": True,
                        "ledgerQuery": True,
                    }
                },
                {
                    "peer0.an-org.a-domain.com": {
                        "url": "grpc://peer0-hlf-peer.peer-namespace.svc.cluster.local:7051",
                        "eventUrl": "grpc://peer0-hlf-peer.peer-namespace.svc.cluster.local:7053",
                    }
                },
            )
        ]
        mock_define_orderers.side_effect = [
            {
                "ord0.a-domain.com": {
                    "url": "grpc://ord0-hlf-ord.orderer-namespace.svc.cluster.local:7050"
                }
            }
        ]
        res = json_ct(
            self.OPTS,
            "a-ca",
            "a-ca.a-domain.com",
            "an-org",
            "a-domain.com",
            "AnMSP",
            "a-channel",
        )
        mock_define_peers.assert_called_once_with(
            ["peer0"],
            ["peer0-hlf-peer.peer-namespace.svc.cluster.local"],
            "an-org",
            "a-domain.com",
        )
        mock_define_orderers.assert_called_once_with(
            ["ord0"], ["ord0-hlf-ord.ord-namespace.svc.cluster.local"], "a-domain.com"
        )
        assert isinstance(res, str)
