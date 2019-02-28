from copy import deepcopy
from unittest import mock
from unittest.mock import call

from nephos.fabric.peer import (
    check_peer,
    setup_peer,
    peer_channel_suffix,
    get_channel_block,
    create_channel,
)
from nephos.helpers.helm import HelmPreserve


class TestCheckPeer:
    OPTS = "opt-values"

    @mock.patch("nephos.fabric.peer.sleep")
    @mock.patch("nephos.fabric.peer.get_pod")
    def test_check_peer(self, mock_get_pod, mock_sleep):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.logs.side_effect = [
            "Not yet started",
            "Not yet started\nStarting peer",
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        check_peer(self.OPTS, "a-release")
        assert mock_pod_ex.logs.call_count == 2
        mock_sleep.assert_called_once_with(15)

    @mock.patch("nephos.fabric.peer.sleep")
    @mock.patch("nephos.fabric.peer.get_pod")
    def test_check_peer_again(self, mock_get_pod, mock_sleep):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.logs.side_effect = [
            "Not yet started\nStarting peer\nReceived block 0"
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        check_peer(self.OPTS, "a-release", verbose=True)
        assert mock_pod_ex.logs.call_count == 1
        mock_sleep.assert_not_called()

    @mock.patch("nephos.fabric.peer.sleep")
    @mock.patch("nephos.fabric.peer.get_pod")
    def test_check_peer_noblocks(self, mock_get_pod, mock_sleep):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.logs.side_effect = ["Not yet started\nStarting peer\nSleeping 5s"]
        mock_get_pod.side_effect = [mock_pod_ex]
        check_peer(self.OPTS, "a-release", verbose=True)
        assert mock_pod_ex.logs.call_count == 1
        mock_sleep.assert_not_called()


class TestSetupPeer:
    OPTS = {
        "core": {"chart_repo": "a-repo", "dir_values": "./a_dir"},
        "msps": {"peer_MSP": {"namespace": "peer-namespace"}},
        "peers": {"msp": "peer_MSP", "names": ["peer0", "peer1"]},
    }

    @mock.patch("nephos.fabric.peer.helm_upgrade")
    @mock.patch("nephos.fabric.peer.helm_install")
    @mock.patch("nephos.fabric.peer.check_peer")
    def test_peer(self, mock_check_peer, mock_helm_install, mock_helm_upgrade):
        OPTS = deepcopy(self.OPTS)
        setup_peer(OPTS)
        mock_helm_install.assert_has_calls(
            [
                call(
                    "a-repo",
                    "hlf-couchdb",
                    "cdb-peer0",
                    "peer-namespace",
                    config_yaml="./a_dir/hlf-couchdb/cdb-peer0.yaml",
                    verbose=False,
                ),
                call(
                    "a-repo",
                    "hlf-peer",
                    "peer0",
                    "peer-namespace",
                    config_yaml="./a_dir/hlf-peer/peer0.yaml",
                    verbose=False,
                ),
                call(
                    "a-repo",
                    "hlf-couchdb",
                    "cdb-peer1",
                    "peer-namespace",
                    config_yaml="./a_dir/hlf-couchdb/cdb-peer1.yaml",
                    verbose=False,
                ),
                call(
                    "a-repo",
                    "hlf-peer",
                    "peer1",
                    "peer-namespace",
                    config_yaml="./a_dir/hlf-peer/peer1.yaml",
                    verbose=False,
                ),
            ]
        )
        mock_helm_upgrade.assert_not_called()
        mock_check_peer.assert_has_calls(
            [
                call("peer-namespace", "peer0", verbose=False),
                call("peer-namespace", "peer1", verbose=False),
            ]
        )

    @mock.patch("nephos.fabric.peer.helm_upgrade")
    @mock.patch("nephos.fabric.peer.helm_install")
    @mock.patch("nephos.fabric.peer.check_peer")
    def test_peer_upgrade(self, mock_check_peer, mock_helm_install, mock_helm_upgrade):
        OPTS = deepcopy(self.OPTS)
        OPTS["peers"]["names"] = ["peer0"]
        setup_peer(OPTS, upgrade=True)
        mock_helm_install.assert_not_called()
        mock_helm_upgrade.assert_has_calls(
            [
                call(
                    "a-repo",
                    "hlf-couchdb",
                    "cdb-peer0",
                    "peer-namespace",
                    config_yaml="./a_dir/hlf-couchdb/cdb-peer0.yaml",
                    preserve=(
                        HelmPreserve(
                            "cdb-peer0-hlf-couchdb",
                            "COUCHDB_USERNAME",
                            "couchdbUsername",
                        ),
                        HelmPreserve(
                            "cdb-peer0-hlf-couchdb",
                            "COUCHDB_PASSWORD",
                            "couchdbPassword",
                        ),
                    ),
                    verbose=False,
                ),
                call(
                    "a-repo",
                    "hlf-peer",
                    "peer0",
                    "peer-namespace",
                    config_yaml="./a_dir/hlf-peer/peer0.yaml",
                    verbose=False,
                ),
            ]
        )
        mock_check_peer.assert_called_once_with(
            "peer-namespace", "peer0", verbose=False
        )


class TestPeerChannelSuffix:
    OPTS = {}

    @mock.patch("nephos.fabric.peer.check_ord_tls")
    def test_peer_channel_suffix(self, mock_check_ord_tls):
        mock_check_ord_tls.side_effect = [True]
        result = peer_channel_suffix(self.OPTS, "ord42", verbose=False)
        mock_check_ord_tls.assert_called_once_with(self.OPTS, verbose=False)
        assert (
            result
            == "--tls --ordererTLSHostnameOverride ord42-hlf-ord --cafile $(ls ${ORD_TLS_PATH}/*.pem)"
        )

    @mock.patch("nephos.fabric.peer.check_ord_tls")
    def test_peer_channel_suffix_notls(self, mock_check_ord_tls):
        mock_check_ord_tls.side_effect = [False]
        result = peer_channel_suffix(self.OPTS, "ord42", verbose=True)
        mock_check_ord_tls.assert_called_once_with(self.OPTS, verbose=True)
        assert result == ""


class TestGetChannelBlock:
    def test_get_channel_block(self):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.execute.side_effect = [
            ("", None),  # Get channel file
            ("some logs", None),  # Fetch existing channel
        ]
        result = get_channel_block(
            mock_pod_ex, "ord42", "ord-namespace", "a-channel", "some-suffix"
        )
        mock_pod_ex.execute.assert_has_calls(
            [
                call("ls /var/hyperledger/a-channel.block"),
                call(
                    "bash -c 'peer channel fetch 0 /var/hyperledger/a-channel.block -c a-channel "
                    + "-o ord42-hlf-ord.ord-namespace.svc.cluster.local:7050 some-suffix'"
                ),
            ]
        )
        assert result is True

    def test_get_channel_block_again(self):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.execute.side_effect = [
            ("/var/hyperledger/a-channel.block", None)  # Get channel file
        ]
        result = get_channel_block(
            mock_pod_ex, "ord42", "ord-namespace", "a-channel", "some-suffix"
        )
        mock_pod_ex.execute.assert_has_calls(
            [call("ls /var/hyperledger/a-channel.block")]
        )
        assert result is True

    def test_get_channel_block_error(self):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.execute.side_effect = [
            ("", None),  # Get channel file
            ("some logs", "some error"),  # Fetch existing channel
        ]
        result = get_channel_block(
            mock_pod_ex, "ord42", "ord-namespace", "a-channel", "some-suffix"
        )
        mock_pod_ex.execute.assert_has_calls(
            [
                call("ls /var/hyperledger/a-channel.block"),
                call(
                    "bash -c 'peer channel fetch 0 /var/hyperledger/a-channel.block -c a-channel "
                    + "-o ord42-hlf-ord.ord-namespace.svc.cluster.local:7050 some-suffix'"
                ),
            ]
        )
        assert result is False


# TODO: Tests too complex, simplify channel creation, etc.
class TestSetupChannel:
    OPTS = {
        "msps": {
            "ord_MSP": {"namespace": "ord-namespace"},
            "peer_MSP": {"namespace": "peer-namespace"},
        },
        "orderers": {"msp": "ord_MSP", "names": ["ord0", "ord1"]},
        "peers": {
            "channel_name": "a-channel",
            "msp": "peer_MSP",
            "names": ["peer0", "peer1"],
        },
    }
    CMD_SUFFIX = "--tls --ordererTLSHostnameOverride ord0-hlf-ord --cafile $(ls ${ORD_TLS_PATH}/*.pem)"

    @mock.patch("nephos.fabric.peer.random")
    @mock.patch("nephos.fabric.peer.peer_channel_suffix")
    @mock.patch("nephos.fabric.peer.get_pod")
    @mock.patch("nephos.fabric.peer.get_channel_block")
    def test_create_channel(
        self,
        mock_get_channel_block,
        mock_get_pod,
        mock_peer_channel_suffix,
        mock_random,
    ):
        mock_random.choice.side_effect = ["ord0"]
        mock_peer_channel_suffix.side_effect = [self.CMD_SUFFIX]
        mock_get_channel_block.side_effect = [False, True, True]
        mock_pod0_ex = mock.Mock()
        mock_pod0_ex.execute.side_effect = [
            ("Create channel", None),
            ("Channels peers has joined: ", None),  # List channels
            ("Join channel", None),
        ]
        mock_pod1_ex = mock.Mock()
        mock_pod1_ex.execute.side_effect = [
            ("Channels peers has joined: ", None),  # List channels
            ("Join channel", None),
        ]
        mock_get_pod.side_effect = [mock_pod0_ex, mock_pod1_ex]
        create_channel(self.OPTS)
        mock_random.choice.assert_called_once_with(self.OPTS["orderers"]["names"])
        mock_peer_channel_suffix.assert_called_once_with(
            self.OPTS, "ord0", verbose=False
        )
        mock_get_pod.assert_has_calls(
            [
                call("peer-namespace", "peer0", "hlf-peer", verbose=False),
                call("peer-namespace", "peer1", "hlf-peer", verbose=False),
            ]
        )
        mock_get_channel_block.assert_has_calls(
            [
                call(
                    mock_pod0_ex, "ord0", "ord-namespace", "a-channel", self.CMD_SUFFIX
                ),
                call(
                    mock_pod0_ex, "ord0", "ord-namespace", "a-channel", self.CMD_SUFFIX
                ),
                call(
                    mock_pod1_ex, "ord0", "ord-namespace", "a-channel", self.CMD_SUFFIX
                ),
            ]
        )
        mock_pod0_ex.execute.assert_has_calls(
            [
                call(
                    "bash -c 'peer channel create -o ord0-hlf-ord.ord-namespace.svc.cluster.local:7050 "
                    + "-c a-channel -f /hl_config/channel/a-channel.tx "
                    + self.CMD_SUFFIX
                    + "'"
                ),
                call("peer channel list"),
                call(
                    "bash -c 'CORE_PEER_MSPCONFIGPATH=$ADMIN_MSP_PATH "
                    + "peer channel join -b /var/hyperledger/a-channel.block "
                    + self.CMD_SUFFIX
                    + "'"
                ),
            ]
        )
        mock_pod1_ex.execute.assert_has_calls(
            [
                call("peer channel list"),
                call(
                    "bash -c 'CORE_PEER_MSPCONFIGPATH=$ADMIN_MSP_PATH "
                    + "peer channel join -b /var/hyperledger/a-channel.block "
                    + self.CMD_SUFFIX
                    + "'"
                ),
            ]
        )

    @mock.patch("nephos.fabric.peer.random")
    @mock.patch("nephos.fabric.peer.peer_channel_suffix")
    @mock.patch("nephos.fabric.peer.get_pod")
    @mock.patch("nephos.fabric.peer.get_channel_block")
    def test_create_channel_again(
        self,
        mock_get_channel_block,
        mock_get_pod,
        mock_peer_channel_suffix,
        mock_random,
    ):
        mock_random.choice.side_effect = ["ord0"]
        mock_peer_channel_suffix.side_effect = [self.CMD_SUFFIX]
        mock_get_channel_block.side_effect = [True, True]
        mock_pod0_ex = mock.Mock()
        mock_pod0_ex.execute.side_effect = [
            ("Channels peers has joined: a-channel", None)  # List channels
        ]
        mock_pod1_ex = mock.Mock()
        mock_pod1_ex.execute.side_effect = [
            ("Channels peers has joined: a-channel", None)  # List channels
        ]
        mock_get_pod.side_effect = [mock_pod0_ex, mock_pod1_ex]
        create_channel(self.OPTS)
        mock_random.choice.assert_called_once_with(self.OPTS["orderers"]["names"])
        mock_peer_channel_suffix.assert_called_once_with(
            self.OPTS, "ord0", verbose=False
        )
        mock_get_pod.assert_has_calls(
            [
                call("peer-namespace", "peer0", "hlf-peer", verbose=False),
                call("peer-namespace", "peer1", "hlf-peer", verbose=False),
            ]
        )
        mock_get_channel_block.assert_has_calls(
            [
                call(
                    mock_pod0_ex, "ord0", "ord-namespace", "a-channel", self.CMD_SUFFIX
                ),
                call(
                    mock_pod1_ex, "ord0", "ord-namespace", "a-channel", self.CMD_SUFFIX
                ),
            ]
        )
        mock_pod0_ex.execute.assert_called_once_with("peer channel list")
        mock_pod1_ex.execute.assert_called_once_with("peer channel list")

    @mock.patch("nephos.fabric.peer.random")
    @mock.patch("nephos.fabric.peer.peer_channel_suffix")
    @mock.patch("nephos.fabric.peer.get_pod")
    @mock.patch("nephos.fabric.peer.get_channel_block")
    def test_create_channel_notls(
        self,
        mock_get_channel_block,
        mock_get_pod,
        mock_peer_channel_suffix,
        mock_random,
    ):
        mock_random.choice.side_effect = ["ord1"]
        mock_peer_channel_suffix.side_effect = [""]
        mock_get_channel_block.side_effect = [False, True, True]
        mock_pod0_ex = mock.Mock()
        mock_pod0_ex.execute.side_effect = [
            ("Create channel", None),
            ("Channels peers has joined: ", None),  # List channels
            ("Join channel", None),
        ]
        mock_pod1_ex = mock.Mock()
        mock_pod1_ex.execute.side_effect = [
            ("Channels peers has joined: ", None),  # List channels
            ("Join channel", None),
        ]
        mock_get_pod.side_effect = [mock_pod0_ex, mock_pod1_ex]
        create_channel(self.OPTS, verbose=True)
        mock_random.choice.assert_called_once_with(self.OPTS["orderers"]["names"])
        mock_peer_channel_suffix.assert_called_once_with(
            self.OPTS, "ord1", verbose=True
        )
        mock_get_pod.assert_has_calls(
            [
                call("peer-namespace", "peer0", "hlf-peer", verbose=True),
                call("peer-namespace", "peer1", "hlf-peer", verbose=True),
            ]
        )
        mock_get_channel_block.assert_has_calls(
            [
                call(mock_pod0_ex, "ord1", "ord-namespace", "a-channel", ""),
                call(mock_pod0_ex, "ord1", "ord-namespace", "a-channel", ""),
                call(mock_pod1_ex, "ord1", "ord-namespace", "a-channel", ""),
            ]
        )
        mock_pod0_ex.execute.assert_has_calls(
            [
                call(
                    "bash -c 'peer channel create -o ord1-hlf-ord.ord-namespace.svc.cluster.local:7050 "
                    + "-c a-channel -f /hl_config/channel/a-channel.tx '"
                ),
                call("peer channel list"),
                call(
                    "bash -c 'CORE_PEER_MSPCONFIGPATH=$ADMIN_MSP_PATH "
                    + "peer channel join -b /var/hyperledger/a-channel.block '"
                ),
            ]
        )
        mock_pod1_ex.execute.assert_has_calls(
            [
                call("peer channel list"),
                call(
                    "bash -c 'CORE_PEER_MSPCONFIGPATH=$ADMIN_MSP_PATH "
                    + "peer channel join -b /var/hyperledger/a-channel.block '"
                ),
            ]
        )
