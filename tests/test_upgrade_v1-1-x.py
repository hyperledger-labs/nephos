from unittest import mock
from unittest.mock import call

import pytest
from kubernetes.client.rest import ApiException

from nephos.upgrade_v11x import extract_credentials, extract_crypto, upgrade_charts


class TestExtractCredentials:
    OPTS = {
        'msps': {
            'ord_MSP': {'namespace': 'ord-namespace'},
            'peer_MSP': {'namespace': 'peer-namespace'}
        },
        'orderers': {'names': ['ord0', 'ord1'], 'msp': 'ord_MSP'},
        'peers': {'names': ['peer0', 'peer1'], 'msp': 'peer_MSP'}
    }

    @mock.patch('nephos.upgrade_v11x.secret_read')
    @mock.patch('nephos.upgrade_v11x.secret_create')
    @mock.patch('nephos.upgrade_v11x.print')
    def test_extract_credentials(self, mock_print, mock_secret_create, mock_secret_read):
        secret_data = [
            {'CA_USERNAME': 'ord0', 'CA_PASSWORD': 'a-password'},
            {'CA_USERNAME': 'ord1', 'CA_PASSWORD': 'a-password'}
        ]
        mock_secret_read.side_effect = [
            ApiException,
            secret_data[0],
            ApiException,
            secret_data[1]
        ]
        extract_credentials(self.OPTS, 'orderer')
        mock_secret_read.assert_has_calls([
            call('hlf--ord0-cred', 'ord-namespace'),
            call('ord0-hlf-ord', 'ord-namespace'),
            call('hlf--ord1-cred', 'ord-namespace'),
            call('ord1-hlf-ord', 'ord-namespace')
        ])
        mock_print.assert_not_called()
        mock_secret_create.assert_has_calls([
            call(secret_data[0], 'hlf--ord0-cred', 'ord-namespace', verbose=False),
            call(secret_data[1], 'hlf--ord1-cred', 'ord-namespace', verbose=False),
        ])

    @mock.patch('nephos.upgrade_v11x.secret_read')
    @mock.patch('nephos.upgrade_v11x.secret_create')
    @mock.patch('nephos.upgrade_v11x.print')
    def test_extract_credentials_again(self, mock_print, mock_secret_create, mock_secret_read):
        mock_secret_read.side_effect = [None, None]
        extract_credentials(self.OPTS, 'peer', verbose=True)
        mock_secret_read.assert_has_calls([
            call('hlf--peer0-cred', 'peer-namespace'),
            call('hlf--peer1-cred', 'peer-namespace')
        ])
        mock_print.assert_has_calls([
            call('hlf--peer0-cred secret already exists'),
            call('hlf--peer1-cred secret already exists')
        ])
        mock_secret_create.assert_not_called()


class TestExtractCrypto:
    OPTS = {
        'msps': {
            'ord_MSP': {'namespace': 'ord-namespace'},
            'peer_MSP': {'namespace': 'peer-namespace'}
        },
        'orderers': {'names': ['ord0'], 'msp': 'ord_MSP'},
        'peers': {'names': ['peer0'], 'msp': 'peer_MSP'}
    }

    @mock.patch('nephos.upgrade_v11x.secret_read')
    @mock.patch('nephos.upgrade_v11x.secret_create')
    @mock.patch('nephos.upgrade_v11x.print')
    @mock.patch('nephos.upgrade_v11x.get_pod')
    def test_extract_crypto(self, mock_get_pod, mock_print, mock_secret_create, mock_secret_read):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.execute.side_effect = [
            '1', 'a-secret',  # signcerts
            '1', 'a-secret',  # keystore
            '1', 'a-secret',  # cacerts
            '0'               # intermediatecerts
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        mock_secret_read.side_effect = [ApiException, ApiException, ApiException, ApiException]
        extract_crypto(self.OPTS, 'orderer')
        mock_get_pod.assert_has_calls([
            call('ord-namespace', 'ord0', 'hlf-ord')
        ])
        mock_secret_read.assert_has_calls([
            call('hlf--ord0-idcert', 'ord-namespace'),
            call('hlf--ord0-idkey', 'ord-namespace'),
            call('hlf--ord0-cacert', 'ord-namespace'),
            call('hlf--ord0-caintcert', 'ord-namespace')
        ])
        mock_pod_ex.execute.assert_has_calls([
            call("bash -c 'ls /var/hyperledger/msp/signcerts' | wc -l"),
            call("bash -c 'cat /var/hyperledger/msp/signcerts/*'"),
            call("bash -c 'ls /var/hyperledger/msp/keystore' | wc -l"),
            call("bash -c 'cat /var/hyperledger/msp/keystore/*'"),
            call("bash -c 'ls /var/hyperledger/msp/cacerts' | wc -l"),
            call("bash -c 'cat /var/hyperledger/msp/cacerts/*'"),
            call("bash -c 'ls /var/hyperledger/msp/intermediatecerts' | wc -l")
        ])
        mock_print.assert_called_once_with('Wrong number of files in intermediatecerts directory')
        mock_secret_create.assert_has_calls([
            call({'cert.pem': 'a-secret'}, 'hlf--ord0-idcert', 'ord-namespace', verbose=False),
            call({'key.pem': 'a-secret'}, 'hlf--ord0-idkey', 'ord-namespace', verbose=False),
            call({'cacert.pem': 'a-secret'}, 'hlf--ord0-cacert', 'ord-namespace', verbose=False)
        ])

    @mock.patch('nephos.upgrade_v11x.secret_read')
    @mock.patch('nephos.upgrade_v11x.secret_create')
    @mock.patch('nephos.upgrade_v11x.print')
    @mock.patch('nephos.upgrade_v11x.get_pod')
    def test_extract_crypto_again(self, mock_get_pod, mock_print, mock_secret_create, mock_secret_read):
        mock_pod_ex = mock.Mock()
        mock_get_pod.side_effect = [mock_pod_ex]
        extract_crypto(self.OPTS, 'peer', verbose=True)
        mock_get_pod.assert_has_calls([
            call('peer-namespace', 'peer0', 'hlf-peer')
        ])
        mock_secret_read.assert_has_calls([
            call('hlf--peer0-idcert', 'peer-namespace'),
            call('hlf--peer0-idkey', 'peer-namespace'),
            call('hlf--peer0-cacert', 'peer-namespace'),
            call('hlf--peer0-caintcert', 'peer-namespace')
        ])
        mock_pod_ex.execute.assert_not_called()
        mock_print.assert_has_calls([
            call('hlf--peer0-idcert secret already exists'),
            call('hlf--peer0-idkey secret already exists'),
            call('hlf--peer0-cacert secret already exists'),
            call('hlf--peer0-caintcert secret already exists')
        ])
        mock_secret_create.assert_not_called()

    @mock.patch('nephos.upgrade_v11x.secret_read')
    @mock.patch('nephos.upgrade_v11x.secret_create')
    @mock.patch('nephos.upgrade_v11x.print')
    @mock.patch('nephos.upgrade_v11x.get_pod')
    def test_extract_crypto_fail(self, mock_get_pod, mock_print, mock_secret_create, mock_secret_read):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.execute.side_effect = [
            '0'  # signcerts
        ]
        mock_get_pod.side_effect = [mock_pod_ex]
        mock_secret_read.side_effect = [ApiException]
        with pytest.raises(ValueError):
            extract_crypto(self.OPTS, 'peer')
        mock_get_pod.assert_has_calls([
            call('peer-namespace', 'peer0', 'hlf-peer')
        ])
        mock_secret_read.assert_called_once_with('hlf--peer0-idcert', 'peer-namespace')
        mock_pod_ex.execute.assert_called_once_with("bash -c 'ls /var/hyperledger/msp/signcerts' | wc -l")
        mock_print.assert_not_called()
        mock_secret_create.assert_not_called()


class TestUpgradeCharts:
    OPTS = {
        'core': {'chart_repo': 'a-repo', 'dir_values': './a_dir'},
        'msps': {
            'ord_MSP': {'namespace': 'ord-namespace'},
            'peer_MSP': {'namespace': 'peer-namespace'}
        },
        'orderers': {'names': ['ord0'], 'msp': 'ord_MSP'},
        'peers': {'names': ['peer0'], 'msp': 'peer_MSP'}
    }

    @mock.patch('nephos.upgrade_v11x.print')
    @mock.patch('nephos.upgrade_v11x.helm_upgrade')
    @mock.patch('nephos.upgrade_v11x.get_pod')
    @mock.patch('nephos.upgrade_v11x.check_peer')
    @mock.patch('nephos.upgrade_v11x.check_ord')
    def test_upgrade_charts(self, mock_check_ord, mock_check_peer,
                            mock_get_pod, mock_helm_upgrade, mock_print):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.execute.side_effect = ['', None]
        mock_get_pod.side_effect = [mock_pod_ex]
        upgrade_charts(self.OPTS, 'orderer')
        mock_pod_ex.execute.assert_has_calls([
            call('ls /var/hyperledger/msp_old'),
            call('mv /var/hyperledger/msp /var/hyperledger/msp_old')
        ])
        mock_print.assert_not_called()
        mock_helm_upgrade.assert_called_once_with(
            'a-repo', 'hlf-ord', 'ord0', 'ord-namespace', config_yaml='./a_dir/hlf-ord/ord0.yaml', verbose=False)
        mock_check_ord.assert_called_once_with('ord-namespace', 'ord0', verbose=False)
        mock_check_peer.assert_not_called()

    @mock.patch('nephos.upgrade_v11x.print')
    @mock.patch('nephos.upgrade_v11x.helm_upgrade')
    @mock.patch('nephos.upgrade_v11x.get_pod')
    @mock.patch('nephos.upgrade_v11x.check_peer')
    @mock.patch('nephos.upgrade_v11x.check_ord')
    def test_upgrade_charts_again(self, mock_check_ord, mock_check_peer,
                                  mock_get_pod, mock_helm_upgrade, mock_print):
        mock_pod_ex = mock.Mock()
        mock_pod_ex.execute.side_effect = ['a-res']
        mock_get_pod.side_effect = [mock_pod_ex]
        upgrade_charts(self.OPTS, 'peer', verbose=True)
        mock_pod_ex.execute.assert_has_calls([
            call('ls /var/hyperledger/msp_old')
        ])
        mock_print.assert_called_once_with('/var/hyperledger/msp_old already exists')
        mock_helm_upgrade.assert_called_once_with(
            'a-repo', 'hlf-peer', 'peer0', 'peer-namespace', config_yaml='./a_dir/hlf-peer/peer0.yaml', verbose=True)
        mock_check_ord.assert_not_called()
        mock_check_peer.assert_called_once_with('peer-namespace', 'peer0', verbose=True)
