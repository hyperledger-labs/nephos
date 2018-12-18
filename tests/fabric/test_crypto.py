from unittest import mock
from unittest.mock import call

import pytest

from fabric.crypto import (register_node, enroll_node, crypto_to_secrets, setup_nodes, setup_blocks, PWD)


class TestRegisterNode:
    @mock.patch('fabric.crypto.get_pod')
    def test_register_node(self, mock_get_pod):
        mock_executor = mock.Mock()
        mock_get_pod.side_effect = [mock_executor]
        mock_executor.execute.side_effect = [None,  # List identities
                                             None]  # Register identities
        register_node('a-namespace', 'a-ca', 'orderer', 'an-ord', 'a-password')
        mock_get_pod.assert_called_once_with(namespace='a-namespace', release='a-ca', app='hlf-ca', verbose=False)
        mock_executor.execute.assert_has_calls([
            call('fabric-ca-client identity list --id an-ord'),
            call('fabric-ca-client register --id.name an-ord --id.secret a-password --id.type orderer')
        ])

    @mock.patch('fabric.crypto.get_pod')
    def test_register_node_again(self, mock_get_pod):
        mock_executor = mock.Mock()
        mock_get_pod.side_effect = [mock_executor]
        mock_executor.execute.side_effect = ['an-ord']  # List identities
        register_node('a-namespace', 'a-ca', 'orderer', 'an-ord', 'a-password', verbose=True)
        mock_get_pod.assert_called_once_with(namespace='a-namespace', release='a-ca', app='hlf-ca', verbose=True)
        mock_executor.execute.assert_called_once_with('fabric-ca-client identity list --id an-ord')


class TestEnrollNode:
    @mock.patch('fabric.crypto.ingress_read')
    @mock.patch('fabric.crypto.execute_until_success')
    def test_enroll_node(self, mock_execute_until_success, mock_ingress_read):
        mock_ingress_read.side_effect = [['an-ingress']]
        OPTS = {'core': {'dir_config': './a_dir', 'namespace': 'a-namespace'},
                'cas': {'a-ca': {'tls_cert': '/some_msp/tls_cert.pem'}}}
        enroll_node(OPTS, 'a-ca', 'an-ord', 'a-password')
        mock_ingress_read.assert_called_once_with('a-ca-hlf-ca', namespace='a-namespace', verbose=False)
        mock_execute_until_success.assert_called_once_with(
            'FABRIC_CA_CLIENT_HOME=./a_dir fabric-ca-client enroll ' +
            '-u https://an-ord:a-password@an-ingress -M an-ord_MSP ' +
            '--tls.certfiles /some_msp/tls_cert.pem')

    @mock.patch('fabric.crypto.path')
    @mock.patch('fabric.crypto.ingress_read')
    @mock.patch('fabric.crypto.execute_until_success')
    def test_enroll_node_again(self, mock_execute_until_success, mock_ingress_read, mock_path):
        mock_ingress_read.side_effect =[['an-ingress']]
        mock_path.join.side_effect = ['./a_dir/a-peer_MSP']
        mock_path.isdir.side_effect = [True]
        OPTS = {'core': {'dir_config': './a_dir', 'namespace': 'a-namespace'},
                'cas': {'a-ca': {'tls_cert': '/some_msp/tls_cert.pem'}}}
        enroll_node(OPTS, 'a-ca', 'a-peer', 'a-password')
        mock_ingress_read.assert_called_once_with('a-ca-hlf-ca', namespace='a-namespace', verbose=False)
        mock_execute_until_success.assert_not_called()

    @mock.patch('fabric.crypto.ingress_read')
    @mock.patch('fabric.crypto.execute_until_success')
    def test_enroll_verbose(self, mock_execute_until_success, mock_ingress_read):
        mock_ingress_read.side_effect =[['an-ingress']]
        OPTS = {'core': {'dir_config': './a_dir', 'namespace': 'a-namespace'},
                'cas': {'a-ca': {'tls_cert': '/some_msp/tls_cert.pem'}}}
        enroll_node(OPTS, 'a-ca', 'a-peer', 'a-password', verbose=True)
        mock_ingress_read.assert_called_once_with('a-ca-hlf-ca', namespace='a-namespace', verbose=True)
        mock_execute_until_success.assert_called_once_with(
            'FABRIC_CA_CLIENT_HOME=./a_dir fabric-ca-client enroll ' +
            '-u https://a-peer:a-password@an-ingress -M a-peer_MSP ' +
            '--tls.certfiles /some_msp/tls_cert.pem')


class TestCryptoToSecrets:

    @mock.patch('fabric.crypto.print')
    @mock.patch('fabric.crypto.crypto_secret')
    def test_crypto_to_secrets(self, mock_crypto_secret, mock_print):
        mock_crypto_secret.side_effect = [None, None, None, None]
        crypto_to_secrets('a-namespace', './a_dir', 'a-user')
        mock_crypto_secret.assert_has_calls([
            call('hlf--a-user-idcert', 'a-namespace',
                 file_path='./a_dir/signcerts', key='cert.pem', verbose=False),
            call('hlf--a-user-idkey', 'a-namespace',
                 file_path='./a_dir/keystore', key='key.pem', verbose=False),
            call('hlf--a-user-cacert', 'a-namespace',
                 file_path='./a_dir/cacerts', key='cacert.pem', verbose=False),
            call('hlf--a-user-caintcert', 'a-namespace',
                 file_path='./a_dir/intermediatecerts', key='intermediatecacert.pem', verbose=False)
        ])
        mock_print.assert_not_called()

    @mock.patch('fabric.crypto.print')
    @mock.patch('fabric.crypto.crypto_secret')
    def test_crypto_to_secrets_notls(self, mock_crypto_secret, mock_print):
        mock_crypto_secret.side_effect = [None, None, None, Exception()]
        crypto_to_secrets('a-namespace', './a_dir', 'a-user', verbose=True)
        mock_crypto_secret.assert_has_calls([
            call('hlf--a-user-idcert', 'a-namespace',
                 file_path='./a_dir/signcerts', key='cert.pem', verbose=True),
            call('hlf--a-user-idkey', 'a-namespace',
                 file_path='./a_dir/keystore', key='key.pem', verbose=True),
            call('hlf--a-user-cacert', 'a-namespace',
                 file_path='./a_dir/cacerts', key='cacert.pem', verbose=True),
            call('hlf--a-user-caintcert', 'a-namespace',
                 file_path='./a_dir/intermediatecerts', key='intermediatecacert.pem', verbose=True)
        ])
        mock_print.assert_called_once_with(
            'No ./a_dir/intermediatecerts found, so secret "hlf--a-user-caintcert" was not created')

    @mock.patch('fabric.crypto.print')
    @mock.patch('fabric.crypto.crypto_secret')
    def test_crypto_to_secrets_nofiles(self, mock_crypto_secret, mock_print):
        mock_crypto_secret.side_effect = [Exception()]
        with pytest.raises(Exception):
            crypto_to_secrets('a-namespace', './a_dir', 'a-user')
        mock_crypto_secret.assert_called_once_with(
            'hlf--a-user-idcert', 'a-namespace', file_path='./a_dir/signcerts', key='cert.pem', verbose=False)
        mock_print.assert_not_called()


class TestSetupNodes:
    @mock.patch('fabric.crypto.register_node')
    @mock.patch('fabric.crypto.enroll_node')
    @mock.patch('fabric.crypto.crypto_to_secrets')
    @mock.patch('fabric.crypto.credentials_secret')
    def test_nodes(self, mock_credentials_secret, mock_crypto_to_secrets,
                         mock_enroll_node, mock_register_node):
        mock_credentials_secret.side_effect = [{'CA_USERNAME': 'peer0', 'CA_PASSWORD': 'peer0-pw'},
                                               {'CA_USERNAME': 'peer1', 'CA_PASSWORD': 'peer1-pw'}]
        mock_enroll_node.side_effect = ['./peer0_MSP', './peer1_MSP']
        OPTS = {'core': {'namespace': 'a-namespace'},
                'peers': {'names': ['peer0', 'peer1'], 'ca': 'ca-peer'}}
        setup_nodes(OPTS, 'peer')
        mock_credentials_secret.assert_has_calls([
            call('hlf--peer0-cred', 'a-namespace', username='peer0', verbose=False),
            call('hlf--peer1-cred', 'a-namespace', username='peer1', verbose=False)
        ])
        mock_register_node.assert_has_calls([
            call('a-namespace', 'ca-peer', 'peer', 'peer0', 'peer0-pw', verbose=False),
            call('a-namespace', 'ca-peer', 'peer', 'peer1', 'peer1-pw', verbose=False)
        ])
        mock_enroll_node.assert_has_calls([
            call(OPTS, 'ca-peer', 'peer0', 'peer0-pw', verbose=False),
            call(OPTS, 'ca-peer', 'peer1', 'peer1-pw', verbose=False)
        ])
        mock_crypto_to_secrets.assert_has_calls([
            call(namespace='a-namespace', msp_path='./peer0_MSP', user='peer0', verbose=False),
            call(namespace='a-namespace', msp_path='./peer1_MSP', user='peer1', verbose=False)
        ])

    @mock.patch('fabric.crypto.register_node')
    @mock.patch('fabric.crypto.enroll_node')
    @mock.patch('fabric.crypto.crypto_to_secrets')
    @mock.patch('fabric.crypto.credentials_secret')
    def test_nodes_ord(self, mock_credentials_secret, mock_crypto_to_secrets,
                         mock_enroll_node, mock_register_node):
        mock_credentials_secret.side_effect = [{'CA_USERNAME': 'ord0', 'CA_PASSWORD': 'ord0-pw'}]
        mock_enroll_node.side_effect = ['./ord0_MSP']
        OPTS = {'core': {'namespace': 'a-namespace'},
                'orderers': {'names': ['ord0'], 'ca': 'ca-ord'}}
        setup_nodes(OPTS, 'orderer')
        mock_credentials_secret.assert_has_calls([
            call('hlf--ord0-cred', 'a-namespace', username='ord0', verbose=False)
        ])
        mock_register_node.assert_has_calls([
            call('a-namespace', 'ca-ord', 'orderer', 'ord0', 'ord0-pw', verbose=False)
        ])
        mock_enroll_node.assert_has_calls([
            call(OPTS, 'ca-ord', 'ord0', 'ord0-pw', verbose=False)
        ])
        mock_crypto_to_secrets.assert_has_calls([
            call(namespace='a-namespace', msp_path='./ord0_MSP', user='ord0', verbose=False)
        ])


class TestSetupBlocks:
    OPTS = {'core': {'dir_config': './a_dir', 'namespace': 'a-namespace'},
            'orderers': {'secret_genesis': 'a-genesis-secret'},
            'peers': {'secret_channel': 'a-channel-secret',
                      'channel_name': 'a-channel', 'channel_profile': 'AProfile'}}

    @mock.patch('fabric.crypto.secret_from_file')
    @mock.patch('fabric.crypto.print')
    @mock.patch('fabric.crypto.path')
    @mock.patch('fabric.crypto.execute')
    @mock.patch('fabric.crypto.chdir')
    def test_blocks(self, mock_chdir, mock_execute, mock_path, mock_print, mock_secret_from_file):
        mock_path.exists.side_effect = [False, False]
        setup_blocks(self.OPTS)
        mock_chdir.assert_has_calls([
            call('./a_dir'),
            call(PWD)
        ])
        mock_path.exists.has_calls([
            call('genesis.block'),
            call('a-channel.tx')
        ])
        mock_execute.assert_has_calls([
            call('configtxgen -profile OrdererGenesis -outputBlock genesis.block', verbose=False),
            call('configtxgen -profile AProfile -channelID a-channel -outputCreateChannelTx a-channel.tx', verbose=False)
        ])
        mock_print.assert_not_called()
        mock_secret_from_file.assert_has_calls([
            call(secret='a-genesis-secret', namespace='a-namespace',
                 key='genesis.block', filename='genesis.block', verbose=False),
            call(secret='a-channel-secret', namespace='a-namespace',
                 key='a-channel.tx', filename='a-channel.tx', verbose=False)
        ])

    @mock.patch('fabric.crypto.secret_from_file')
    @mock.patch('fabric.crypto.print')
    @mock.patch('fabric.crypto.path')
    @mock.patch('fabric.crypto.execute')
    @mock.patch('fabric.crypto.chdir')
    def test_again(self, mock_chdir, mock_execute, mock_path, mock_print, mock_secret_from_file):
        mock_path.exists.side_effect = [True, True]
        setup_blocks(self.OPTS, True)
        mock_chdir.assert_has_calls([
            call('./a_dir'),
            call(PWD)
        ])
        mock_path.exists.has_calls([
            call('genesis.block'),
            call('a-channel.tx')
        ])
        mock_execute.assert_not_called()
        mock_print.assert_has_calls([
            call('genesis.block already exists'),
            call('a-channel.tx already exists')
        ])
        mock_secret_from_file.assert_has_calls([
            call(secret='a-genesis-secret', namespace='a-namespace',
                 key='genesis.block', filename='genesis.block', verbose=True),
            call(secret='a-channel-secret', namespace='a-namespace',
                 key='a-channel.tx', filename='a-channel.tx', verbose=True)
        ])
