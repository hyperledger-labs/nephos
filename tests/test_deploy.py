from unittest import mock
from unittest.mock import call

from click.testing import CliRunner

from nephos.deploy import cli

RUNNER = CliRunner()


def test_cli():
    result = RUNNER.invoke(cli)
    assert result.exit_code == 0
    assert 'Nephos helps you install Hyperledger Fabric on Kubernetes' in result.output


@mock.patch('nephos.deploy.runner_ca')
@mock.patch('nephos.deploy.load_config')
def test_ca(mock_load_config, mock_runner_ca):
    mock_load_config.side_effect = ['some-opts']
    result = RUNNER.invoke(cli, ['--settings_file', 'nephos_config.yaml', 'ca'])
    mock_load_config.assert_called_once_with('nephos_config.yaml')
    mock_runner_ca.assert_called_once_with('some-opts', upgrade=False, verbose=False)
    assert result.exit_code == 0


@mock.patch('nephos.deploy.runner_composer')
@mock.patch('nephos.deploy.load_config')
def test_composer(mock_load_config, mock_runner_composer):
    mock_load_config.side_effect = ['some-opts']
    result = RUNNER.invoke(cli, ['--settings_file', 'nephos_config.yaml', 'composer'])
    mock_load_config.assert_called_once_with('nephos_config.yaml')
    mock_runner_composer.assert_called_once_with('some-opts', upgrade=False, verbose=False)
    assert result.exit_code == 0


@mock.patch('nephos.deploy.runner_crypto')
@mock.patch('nephos.deploy.load_config')
def test_crypto(mock_load_config, mock_runner_crypto):
    mock_load_config.side_effect = ['some-opts']
    result = RUNNER.invoke(cli, ['--settings_file', 'nephos_config.yaml', 'crypto'])
    mock_load_config.assert_called_once_with('nephos_config.yaml')
    mock_runner_crypto.assert_called_once_with('some-opts', verbose=False)
    assert result.exit_code == 0


@mock.patch('nephos.deploy.runner_deploy')
@mock.patch('nephos.deploy.load_config')
def test_deploy(mock_load_config, mock_runner_deploy):
    mock_load_config.side_effect = ['some-opts']
    result = RUNNER.invoke(cli, ['--settings_file', 'nephos_config.yaml', 'deploy'])
    mock_load_config.assert_called_once_with('nephos_config.yaml')
    mock_runner_deploy.assert_called_once_with('some-opts', upgrade=False, verbose=False)
    assert result.exit_code == 0


@mock.patch('nephos.deploy.runner_fabric')
@mock.patch('nephos.deploy.load_config')
def test_fabric(mock_load_config, mock_runner_fabric):
    mock_load_config.side_effect = ['some-opts']
    result = RUNNER.invoke(cli, ['--settings_file', 'nephos_config.yaml', 'fabric'])
    mock_load_config.assert_called_once_with('nephos_config.yaml')
    mock_runner_fabric.assert_called_once_with('some-opts', upgrade=False, verbose=False)
    assert result.exit_code == 0


@mock.patch('nephos.deploy.runner_orderer')
@mock.patch('nephos.deploy.load_config')
def test_orderer(mock_load_config, mock_runner_orderer):
    mock_load_config.side_effect = ['some-opts']
    result = RUNNER.invoke(cli, ['--settings_file', 'nephos_config.yaml', 'orderer'])
    mock_load_config.assert_called_once_with('nephos_config.yaml')
    mock_runner_orderer.assert_called_once_with('some-opts', upgrade=False, verbose=False)
    assert result.exit_code == 0


@mock.patch('nephos.deploy.runner_peer')
@mock.patch('nephos.deploy.load_config')
def test_peer(mock_load_config, mock_runner_peer):
    mock_load_config.side_effect = ['some-opts']
    result = RUNNER.invoke(cli, ['--settings_file', 'nephos_config.yaml', 'peer'])
    mock_load_config.assert_called_once_with('nephos_config.yaml')
    mock_runner_peer.assert_called_once_with('some-opts', upgrade=False, verbose=False)
    assert result.exit_code == 0


class TestSettings:
    @mock.patch('nephos.deploy.print')
    @mock.patch('nephos.deploy.load_config')
    def test_settings(self, mock_load_config, mock_print):
        mock_load_config.side_effect = ['some-opts']
        result = RUNNER.invoke(cli, ['--settings_file', 'nephos_config.yaml', 'settings'])
        mock_load_config.assert_called_once_with('nephos_config.yaml')
        mock_print.assert_called_once_with('Settings successfully loaded...\n')
        assert result.exit_code == 0

    @mock.patch('nephos.deploy.print')
    @mock.patch('nephos.deploy.load_config')
    def test_settings_verbose(self, mock_load_config, mock_print):
        mock_load_config.side_effect = [{"key": "value"}]
        result = RUNNER.invoke(cli, ['-v', '--settings_file', 'nephos_config.yaml', 'settings'])
        mock_load_config.assert_called_once_with('nephos_config.yaml')
        mock_print.assert_has_calls([
            call('Settings successfully loaded...\n'),
            call('{\n    "key": "value"\n}')
        ])
        assert result.exit_code == 0
