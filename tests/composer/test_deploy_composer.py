from unittest.mock import call, patch

from click.testing import CliRunner

from nephos.deploy import cli

RUNNER = CliRunner()


def test_cli():
    result = RUNNER.invoke(cli)
    assert result.exit_code == 0
    assert "Nephos helps you install Hyperledger Fabric on Kubernetes" in result.output


@patch("nephos.deploy.runner_composer")
@patch("nephos.deploy.load_config")
def test_composer(mock_load_config, mock_runner_composer):
    mock_load_config.side_effect = ["some-opts"]
    result = RUNNER.invoke(cli, ["--settings_file", "nephos_config.yaml", "composer"])
    mock_load_config.assert_called_once_with("nephos_config.yaml")
    mock_runner_composer.assert_called_once_with("some-opts", upgrade=False)
    assert result.exit_code == 0


@patch("nephos.deploy.runner_composer_up")
@patch("nephos.deploy.load_config")
def test_composer_up(mock_load_config, mock_runner_composer_up):
    mock_load_config.side_effect = ["some-opts"]
    result = RUNNER.invoke(
        cli, ["--settings_file", "nephos_config.yaml", "composer-up"]
    )
    mock_load_config.assert_called_once_with("nephos_config.yaml")
    mock_runner_composer_up.assert_called_once_with("some-opts")
    assert result.exit_code == 0
