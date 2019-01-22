from unittest import mock
from unittest.mock import call

from nephos.composer.upgrade import upgrade_network


class TestUpgradeNetwork:
    OPTS = {
        'cas': {'peer-ca': {'org-admin': 'an-admin'}},
        'msps': {'peer_MSP': {'namespace': 'peer-namespace'}},
        'peers': {'ca': 'peer-ca', 'msp': 'peer_MSP'}
    }

    @mock.patch('nephos.composer.upgrade.get_pod')
    def test_upgrade_network(self, mock_get_pod):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.execute.side_effect = [
            ('a-network_a-version.bna', None),
            ('Business network version: another-version', None),
            ('Network install', None),  # network install
            ('Network upgrade', None)  # network upgrade
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        upgrade_network(self.OPTS)
        mock_get_pod.assert_called_once_with('peer-namespace', 'hlc', 'hl-composer', verbose=False)
        mock_pod_ex.execute.assert_has_calls([
            call('ls /hl_config/blockchain_network'),
            call('composer network ping --card an-admin@a-network'),
            call('composer network install --card PeerAdmin@hlfv1 ' +
                 '--archiveFile /hl_config/blockchain_network/a-network_a-version.bna'),
            call('composer network upgrade --card PeerAdmin@hlfv1 ' +
                 '--networkName a-network --networkVersion a-version')
        ])

    @mock.patch('nephos.composer.upgrade.get_pod')
    def test_upgrade_network_again(self, mock_get_pod):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.execute.side_effect = [
            ('a-network_a-version.bna', None),
            ('Business network version: a-version', None)
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        upgrade_network(self.OPTS, verbose=True)
        mock_get_pod.assert_called_once_with('peer-namespace', 'hlc', 'hl-composer', verbose=True)
        mock_pod_ex.execute.assert_has_calls([
            call('ls /hl_config/blockchain_network'),
            call('composer network ping --card an-admin@a-network')
        ])
