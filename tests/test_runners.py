from copy import deepcopy
from unittest import mock
from unittest.mock import call


from nephos.runners import (
    runner_ca,
    runner_composer,
    runner_composer_up,
    runner_crypto,
    runner_deploy,
    runner_fabric,
    runner_orderer,
    runner_peer,
)


class TestRunnerCa:
    OPTS = {"cas": {"a-ca": {}}}

    @mock.patch("nephos.runners.setup_ca")
    @mock.patch("nephos.runners.print")
    def test_runner_ca(self, mock_print, mock_setup_ca):
        opts = deepcopy(self.OPTS)
        runner_ca(opts, upgrade=False)
        mock_setup_ca.assert_called_once_with(opts, upgrade=False, verbose=False)
        mock_print.assert_not_called()

    @mock.patch("nephos.runners.setup_ca")
    @mock.patch("nephos.runners.print")
    def test_runner_ca_cryptogen(self, mock_print, mock_setup_ca):
        opts = deepcopy(self.OPTS)
        del opts["cas"]["a-ca"]
        runner_ca(opts, upgrade=False)
        mock_setup_ca.assert_not_called()
        mock_print.assert_called_once_with(
            "No CAs defined in Nephos settings, ignoring CA setup"
        )


class TestRunnerComposer:
    OPTS = "some-self.OPTS"

    @mock.patch("nephos.runners.setup_admin")
    @mock.patch("nephos.runners.install_network")
    @mock.patch("nephos.runners.deploy_composer")
    def test_runner_composer(
        self, mock_deploy_composer, mock_install_network, mock_setup_admin
    ):
        runner_composer(self.OPTS, upgrade=False)
        mock_deploy_composer.assert_called_once_with(
            self.OPTS, upgrade=False, verbose=False
        )
        mock_setup_admin.assert_called_once_with(self.OPTS, verbose=False)
        mock_install_network.assert_called_once_with(self.OPTS, verbose=False)


class TestRunnerComposerUp:
    OPTS = "some-self.OPTS"

    @mock.patch("nephos.runners.upgrade_network")
    def test_runner_composer_up(self, mock_upgrade_network):
        runner_composer_up(self.OPTS)
        mock_upgrade_network.assert_called_once_with(self.OPTS, verbose=False)


class TestRunnerCrypto:
    OPTS = {"orderers": {"msp": "ord_MSP"}, "peers": {"msp": "peer_MSP"}}

    @mock.patch("nephos.runners.setup_nodes")
    @mock.patch("nephos.runners.genesis_block")
    @mock.patch("nephos.runners.channel_tx")
    @mock.patch("nephos.runners.admin_msp")
    def test_runner_crypto(
        self, mock_admin_msp, mock_channel_tx, mock_genesis_block, mock_setup_nodes
    ):
        runner_crypto(self.OPTS)
        mock_admin_msp.assert_has_calls(
            [
                call(self.OPTS, "ord_MSP", verbose=False),
                call(self.OPTS, "peer_MSP", verbose=False),
            ]
        )
        mock_genesis_block.assert_called_once_with(self.OPTS, verbose=False)
        mock_channel_tx.assert_called_once_with(self.OPTS, verbose=False)
        # Setup node MSPs
        mock_setup_nodes.assert_has_calls(
            [
                call(self.OPTS, "orderer", verbose=False),
                call(self.OPTS, "peer", verbose=False),
            ]
        )


class TestRunnerDeploy:
    OPTS = "some-self.OPTS"

    @mock.patch("nephos.runners.runner_fabric")
    @mock.patch("nephos.runners.runner_composer")
    def test_runner_deploy(self, mock_runner_composer, mock_runner_fabric):
        runner_deploy(self.OPTS, upgrade=False)
        mock_runner_fabric.assert_called_once_with(
            self.OPTS, upgrade=False, verbose=False
        )
        mock_runner_composer.assert_called_once_with(
            self.OPTS, upgrade=False, verbose=False
        )


class TestRunnerFabric:
    OPTS = "some-self.OPTS"

    @mock.patch("nephos.runners.runner_peer")
    @mock.patch("nephos.runners.runner_orderer")
    @mock.patch("nephos.runners.runner_crypto")
    @mock.patch("nephos.runners.runner_ca")
    def test_runner_fabric(
        self, mock_runner_ca, mock_runner_crypto, mock_runner_orderer, mock_runner_peer
    ):
        runner_fabric(self.OPTS, upgrade=False)
        mock_runner_ca.assert_called_once_with(self.OPTS, upgrade=False, verbose=False)
        mock_runner_crypto.assert_called_once_with(self.OPTS, verbose=False)
        mock_runner_orderer.assert_called_once_with(
            self.OPTS, upgrade=False, verbose=False
        )
        mock_runner_peer.assert_called_once_with(
            self.OPTS, upgrade=False, verbose=False
        )


class TestRunnerOrderer:
    OPTS = "some-self.OPTS"

    @mock.patch("nephos.runners.setup_ord")
    def test_runner_orderer(self, mock_setup_ord):
        runner_orderer(self.OPTS, upgrade=False)
        mock_setup_ord.assert_called_once_with(self.OPTS, upgrade=False, verbose=False)


class TestRunnerPeer:
    OPTS = "some-self.OPTS"

    @mock.patch("nephos.runners.setup_peer")
    @mock.patch("nephos.runners.create_channel")
    def test_runner_peer(self, mock_setup_channel, mock_setup_peer):
        runner_peer(self.OPTS, upgrade=False)
        mock_setup_peer.assert_called_once_with(self.OPTS, upgrade=False, verbose=False)
        mock_setup_channel.assert_called_once_with(self.OPTS, verbose=False)
