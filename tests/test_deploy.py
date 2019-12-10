from unittest.mock import call, patch

from click.testing import CliRunner

from nephos.deploy import cli

RUNNER = CliRunner()


def test_cli():
    result = RUNNER.invoke(cli)
    assert result.exit_code == 0
    assert "Nephos helps you install Hyperledger Fabric on Kubernetes" in result.output


@patch("nephos.deploy.runner_ca")
@patch("nephos.deploy.load_config")
def test_cert_auth(mock_load_config, mock_runner_ca):
    mock_load_config.side_effect = ["some-opts"]
    result = RUNNER.invoke(cli, ["--settings_file", "nephos_config.yaml", "cert-auth"])
    mock_load_config.assert_called_once_with("nephos_config.yaml")
    mock_runner_ca.assert_called_once_with("some-opts", upgrade=False)
    assert result.exit_code == 0


@patch("nephos.deploy.runner_crypto")
@patch("nephos.deploy.load_config")
def test_crypto(mock_load_config, mock_runner_crypto):
    mock_load_config.side_effect = ["some-opts"]
    result = RUNNER.invoke(cli, ["--settings_file", "nephos_config.yaml", "crypto"])
    mock_load_config.assert_called_once_with("nephos_config.yaml")
    mock_runner_crypto.assert_called_once_with("some-opts")
    assert result.exit_code == 0


@patch("nephos.deploy.runner_deploy")
@patch("nephos.deploy.load_config")
def test_deploy(mock_load_config, mock_runner_deploy):
    mock_load_config.side_effect = ["some-opts"]
    result = RUNNER.invoke(cli, ["--settings_file", "nephos_config.yaml", "deploy"])
    mock_load_config.assert_called_once_with("nephos_config.yaml")
    mock_runner_deploy.assert_called_once_with("some-opts", upgrade=False)
    assert result.exit_code == 0


@patch("nephos.deploy.runner_fabric")
@patch("nephos.deploy.load_config")
def test_fabric(mock_load_config, mock_runner_fabric):
    mock_load_config.side_effect = ["some-opts"]
    result = RUNNER.invoke(cli, ["--settings_file", "nephos_config.yaml", "fabric"])
    mock_load_config.assert_called_once_with("nephos_config.yaml")
    mock_runner_fabric.assert_called_once_with("some-opts", upgrade=False)
    assert result.exit_code == 0


@patch("nephos.deploy.runner_orderer")
@patch("nephos.deploy.load_config")
def test_orderer(mock_load_config, mock_runner_orderer):
    mock_load_config.side_effect = ["some-opts"]
    result = RUNNER.invoke(cli, ["--settings_file", "nephos_config.yaml", "orderer"])
    mock_load_config.assert_called_once_with("nephos_config.yaml")
    mock_runner_orderer.assert_called_once_with("some-opts", upgrade=False)
    assert result.exit_code == 0


@patch("nephos.deploy.runner_peer")
@patch("nephos.deploy.load_config")
def test_peer(mock_load_config, mock_runner_peer):
    mock_load_config.side_effect = ["some-opts"]
    result = RUNNER.invoke(cli, ["--settings_file", "nephos_config.yaml", "peer"])
    mock_load_config.assert_called_once_with("nephos_config.yaml")
    mock_runner_peer.assert_called_once_with("some-opts", upgrade=False)
    assert result.exit_code == 0


class TestSettings:
    @patch("nephos.deploy.pretty_print")
    @patch("nephos.deploy.logging")
    @patch("nephos.deploy.load_config")
    def test_settings(self, mock_load_config, mock_log, mock_pretty_print):
        mock_load_config.side_effect = [{"key": "value"}]
        result = RUNNER.invoke(
            cli, ["-v", "--settings_file", "nephos_config.yaml", "settings"]
        )
        mock_load_config.assert_called_once_with("nephos_config.yaml")
        mock_log.info.assert_called_once_with("Settings successfully loaded...\n")
        mock_pretty_print.assert_called_once_with('{\n    "key": "value"\n}')
        assert result.exit_code == 0
