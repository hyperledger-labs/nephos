from copy import deepcopy
from unittest import mock
from unittest.mock import call

from nephos.fabric.peer import check_ord_tls, check_peer, setup_peer, setup_channel


class TestCheckOrdTls:
    OPTS = {
        'msps': {'ord_MSP': {'namespace': 'orderer-namespace'}},
        'orderers': {'names': ['an-ord'], 'msp': 'ord_MSP'}
    }

    @mock.patch('nephos.fabric.peer.execute')
    def test_check_ord_tls(self, mock_execute):
        mock_execute.side_effect = [('value', None)]
        check_ord_tls(self.OPTS)
        mock_execute.assert_called_once_with(
            'kubectl get cm -n orderer-namespace an-ord-hlf-ord--ord -o jsonpath="{.data.ORDERER_GENERAL_TLS_ENABLED}"',
            verbose=False)

    @mock.patch('nephos.fabric.peer.execute')
    def test_check_ord_tls_verbose(self, mock_execute):
        mock_execute.side_effect = [('value', None)]
        check_ord_tls(self.OPTS, verbose=True)
        mock_execute.assert_called_once_with(
            'kubectl get cm -n orderer-namespace an-ord-hlf-ord--ord -o jsonpath="{.data.ORDERER_GENERAL_TLS_ENABLED}"',
            verbose=True)


class TestCheckPeer:
    OPTS = 'opt-values'

    @mock.patch('nephos.fabric.peer.sleep')
    @mock.patch('nephos.fabric.peer.get_pod')
    def test_check_peer(self, mock_get_pod, mock_sleep):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.logs.side_effect = [
            'Not yet started',
            'Not yet started\nStarting peer'
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        check_peer(self.OPTS, 'a-release')
        assert mock_pod_ex.logs.call_count == 2
        mock_sleep.assert_called_once_with(15)

    @mock.patch('nephos.fabric.peer.sleep')
    @mock.patch('nephos.fabric.peer.get_pod')
    def test_check_peer_again(self, mock_get_pod, mock_sleep):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.logs.side_effect = [
            'Not yet started\nStarting peer\nReceived block 0'
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        check_peer(self.OPTS, 'a-release', verbose=True)
        assert mock_pod_ex.logs.call_count == 1
        mock_sleep.assert_not_called()

    @mock.patch('nephos.fabric.peer.sleep')
    @mock.patch('nephos.fabric.peer.get_pod')
    def test_check_peer_noblocks(self, mock_get_pod, mock_sleep):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.logs.side_effect = [
            'Not yet started\nStarting peer\nSleeping 5s'
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        check_peer(self.OPTS, 'a-release', verbose=True)
        assert mock_pod_ex.logs.call_count == 1
        mock_sleep.assert_not_called()


class TestSetupPeer:
    OPTS = {
        'core': {'chart_repo': 'a-repo', 'dir_values': './a_dir'},
        'msps': {'peer_MSP': {'namespace': 'peer-namespace'}},
        'peers': {'msp': 'peer_MSP', 'names': ['peer0', 'peer1']}
    }

    @mock.patch('nephos.fabric.peer.helm_upgrade')
    @mock.patch('nephos.fabric.peer.helm_install')
    @mock.patch('nephos.fabric.peer.check_peer')
    def test_peer(self, mock_check_peer, mock_helm_install, mock_helm_upgrade):
        OPTS = deepcopy(self.OPTS)
        setup_peer(OPTS)
        mock_helm_install.assert_has_calls([
            call('a-repo', 'hlf-couchdb', 'cdb-peer0', 'peer-namespace',
                 config_yaml='./a_dir/hlf-couchdb/cdb-peer0.yaml', verbose=False),
            call('a-repo', 'hlf-peer', 'peer0', 'peer-namespace',
                 config_yaml='./a_dir/hlf-peer/peer0.yaml', verbose=False),
            call('a-repo', 'hlf-couchdb', 'cdb-peer1', 'peer-namespace',
                 config_yaml='./a_dir/hlf-couchdb/cdb-peer1.yaml', verbose=False),
            call('a-repo', 'hlf-peer', 'peer1', 'peer-namespace',
                 config_yaml='./a_dir/hlf-peer/peer1.yaml', verbose=False),
        ])
        mock_helm_upgrade.assert_not_called()
        mock_check_peer.assert_has_calls([
            call('peer-namespace', 'peer0', verbose=False),
            call('peer-namespace', 'peer1', verbose=False)
        ])

    @mock.patch('nephos.fabric.peer.helm_upgrade')
    @mock.patch('nephos.fabric.peer.helm_install')
    @mock.patch('nephos.fabric.peer.check_peer')
    def test_peer_upgrade(self, mock_check_peer, mock_helm_install, mock_helm_upgrade):
        OPTS = deepcopy(self.OPTS)
        OPTS['peers']['names'] = ['peer0']
        setup_peer(OPTS, upgrade=True)
        mock_helm_install.assert_not_called()
        mock_helm_upgrade.assert_called_once_with(
            'a-repo', 'hlf-peer', 'peer0', 'peer-namespace',
            config_yaml='./a_dir/hlf-peer/peer0.yaml', verbose=False
        )
        mock_check_peer.assert_called_once_with('peer-namespace', 'peer0', verbose=False)


# TODO: Tests too complex, simplify channel creation, etc.
class TestSetupChannel:
    OPTS = {
        'msps': {'ord_MSP': {'namespace': 'ord-namespace'},
                 'peer_MSP': {'namespace': 'peer-namespace'}},
        'orderers': {'msp': 'ord_MSP', 'names': ['ord0', 'ord1']},
        'peers': {'channel_name': 'a-channel', 'msp': 'peer_MSP', 'names': ['peer0', 'peer1']}
    }
    CMD_SUFFIX = '--tls --ordererTLSHostnameOverride ord0-hlf-ord --cafile $(ls ${ORD_TLS_PATH}/*.pem)'

    @mock.patch('nephos.fabric.peer.random')
    @mock.patch('nephos.fabric.peer.get_pod')
    @mock.patch('nephos.fabric.peer.check_ord_tls')
    def test_channel(self, mock_check_ord_tls, mock_get_pod, mock_random):
        mock_random.choice.side_effect = ['ord0']
        mock_pod0_ex = mock.Mock()
        mock_pod0_ex.execute.side_effect = [
            None,  # Get block
            None,  # Create channel
            None,  # Fetch channel
            'a-channel.block',  # Get block
            'Channels peers has joined: ',  # List channels
            None   # Join channel
        ]
        mock_pod1_ex = mock.Mock()
        mock_pod1_ex.execute.side_effect = [
            None,  # Get block
            None,  # Fetch channel
            'a-channel.block',  # Get block
            'Channels peers has joined: ',  # List channels
            None   # Join channel
        ]
        mock_get_pod.side_effect = [mock_pod0_ex, mock_pod1_ex]
        mock_check_ord_tls.side_effect = ['a-tls']
        setup_channel(self.OPTS)
        mock_random.choice.assert_called_once_with(self.OPTS['orderers']['names'])
        mock_check_ord_tls.assert_called_once_with(self.OPTS, verbose=False)
        mock_get_pod.assert_has_calls([
            call('peer-namespace', 'peer0', 'hlf-peer', verbose=False),
            call('peer-namespace', 'peer1', 'hlf-peer', verbose=False),
        ])
        mock_pod0_ex.execute.assert_has_calls([
            call('ls /var/hyperledger/a-channel.block'),
            call("bash -c 'peer channel create -o ord0-hlf-ord.ord-namespace.svc.cluster.local:7050 " +
                 "-c a-channel -f /hl_config/channel/a-channel.tx " + self.CMD_SUFFIX + "'"),
            call("bash -c 'peer channel fetch 0 /var/hyperledger/a-channel.block " +
                 "-c a-channel -o ord0-hlf-ord.ord-namespace.svc.cluster.local:7050 " + self.CMD_SUFFIX + "'"),
            call('ls /var/hyperledger/a-channel.block'),
            call('peer channel list'),
            call("bash -c 'CORE_PEER_MSPCONFIGPATH=$ADMIN_MSP_PATH " +
                 "peer channel join -b /var/hyperledger/a-channel.block " + self.CMD_SUFFIX + "'")
        ])
        mock_pod1_ex.execute.assert_has_calls([
            call('ls /var/hyperledger/a-channel.block'),
            call("bash -c 'peer channel fetch 0 /var/hyperledger/a-channel.block " +
                 "-c a-channel -o ord0-hlf-ord.ord-namespace.svc.cluster.local:7050 " + self.CMD_SUFFIX + "'"),
            call('ls /var/hyperledger/a-channel.block'),
            call('peer channel list'),
            call("bash -c 'CORE_PEER_MSPCONFIGPATH=$ADMIN_MSP_PATH " +
                 "peer channel join -b /var/hyperledger/a-channel.block " + self.CMD_SUFFIX + "'")
        ])

    @mock.patch('nephos.fabric.peer.random')
    @mock.patch('nephos.fabric.peer.get_pod')
    @mock.patch('nephos.fabric.peer.check_ord_tls')
    def test_channel_again(self, mock_check_ord_tls, mock_get_pod, mock_random):
        mock_random.choice.side_effect = ['ord0']
        mock_pod0_ex = mock.Mock()
        mock_pod0_ex.execute.side_effect = [
            'a-channel.block',  # Get block
            'Channels peers has joined: a-channel',  # List channels
        ]
        mock_pod1_ex = mock.Mock()
        mock_pod1_ex.execute.side_effect = [
            'a-channel.block',  # Get block
            'Channels peers has joined: a-channel',  # List channels
        ]
        mock_get_pod.side_effect = [mock_pod0_ex, mock_pod1_ex]
        mock_check_ord_tls.side_effect = ['a-tls']
        setup_channel(self.OPTS)
        mock_random.choice.assert_called_once_with(self.OPTS['orderers']['names'])
        mock_check_ord_tls.assert_called_once_with(self.OPTS, verbose=False)
        mock_get_pod.assert_has_calls([
            call('peer-namespace', 'peer0', 'hlf-peer', verbose=False),
            call('peer-namespace', 'peer1', 'hlf-peer', verbose=False),
        ])
        mock_pod0_ex.execute.assert_has_calls([
            call('ls /var/hyperledger/a-channel.block'),
            call('peer channel list')
        ])
        mock_pod1_ex.execute.assert_has_calls([
            call('ls /var/hyperledger/a-channel.block'),
            call('peer channel list')
        ])

    @mock.patch('nephos.fabric.peer.random')
    @mock.patch('nephos.fabric.peer.get_pod')
    @mock.patch('nephos.fabric.peer.check_ord_tls')
    def test_channel_notls(self, mock_check_ord_tls, mock_get_pod, mock_random):
        mock_random.choice.side_effect = ['ord1']
        mock_pod0_ex = mock.Mock()
        mock_pod0_ex.execute.side_effect = [
            None,  # Get block
            None,  # Create channel
            None,  # Fetch channel
            'a-channel.block',  # Get block
            'Channels peers has joined: ',  # List channels
            None   # Join channel
        ]
        mock_pod1_ex = mock.Mock()
        mock_pod1_ex.execute.side_effect = [
            None,  # Get block
            None,  # Fetch channel
            'a-channel.block',  # Get block
            'Channels peers has joined: ',  # List channels
            None   # Join channel
        ]
        mock_get_pod.side_effect = [mock_pod0_ex, mock_pod1_ex]
        mock_check_ord_tls.side_effect = [None]
        setup_channel(self.OPTS, verbose=True)
        mock_random.choice.assert_called_once_with(self.OPTS['orderers']['names'])
        mock_check_ord_tls.assert_called_once_with(self.OPTS, verbose=True)
        mock_get_pod.assert_has_calls([
            call('peer-namespace', 'peer0', 'hlf-peer', verbose=True),
            call('peer-namespace', 'peer1', 'hlf-peer', verbose=True),
        ])
        mock_pod0_ex.execute.assert_has_calls([
            call('ls /var/hyperledger/a-channel.block'),
            call("bash -c 'peer channel create -o ord1-hlf-ord.ord-namespace.svc.cluster.local:7050 " +
                 "-c a-channel -f /hl_config/channel/a-channel.tx '"),
            call("bash -c 'peer channel fetch 0 /var/hyperledger/a-channel.block " +
                 "-c a-channel -o ord1-hlf-ord.ord-namespace.svc.cluster.local:7050 '"),
            call('ls /var/hyperledger/a-channel.block'),
            call('peer channel list'),
            call("bash -c 'CORE_PEER_MSPCONFIGPATH=$ADMIN_MSP_PATH " +
                 "peer channel join -b /var/hyperledger/a-channel.block '")
        ])
        mock_pod1_ex.execute.assert_has_calls([
            call('ls /var/hyperledger/a-channel.block'),
            call("bash -c 'peer channel fetch 0 /var/hyperledger/a-channel.block " +
                 "-c a-channel -o ord1-hlf-ord.ord-namespace.svc.cluster.local:7050 '"),
            call('ls /var/hyperledger/a-channel.block'),
            call('peer channel list'),
            call("bash -c 'CORE_PEER_MSPCONFIGPATH=$ADMIN_MSP_PATH " +
                 "peer channel join -b /var/hyperledger/a-channel.block '")
        ])
