from unittest.mock import patch
from copy import deepcopy

from kubernetes.client.rest import ApiException
import pytest

from nephos.fabric.utils import (
    credentials_secret,
    crypto_secret,
    get_pod,
    get_helm_pod,
    get_orderers,
    get_peers,
    get_msps,
    get_channels,
    get_secret_genesis,
    get_kafka_configs,
    get_an_orderer_msp,
    is_orderer_msp,
    get_org_tls_ca_cert,
    is_orderer_tls_true,
    get_tls_path,
    rename_file
)


class TestCredentialsSecret:
    SECRET_DATA = {"CA_USERNAME": "a-user", "CA_PASSWORD": "a-password"}

    @patch("nephos.fabric.utils.secret_read")
    @patch("nephos.fabric.utils.secret_create")
    @patch("nephos.fabric.utils.rand_string")
    def test_credentials_secret(
        self, mock_rand_string, mock_secret_create, mock_secret_read
    ):
        mock_secret_read.side_effect = [ApiException]
        mock_rand_string.side_effect = ["a-password"]
        credentials_secret("a-secret", "a-namespace", "a-user")
        mock_secret_read.assert_called_once_with("a-secret", "a-namespace")
        mock_rand_string.assert_called_once_with(24)
        mock_secret_create.assert_called_once_with(
            self.SECRET_DATA, "a-secret", "a-namespace"
        )

    @patch("nephos.fabric.utils.secret_read")
    @patch("nephos.fabric.utils.secret_create")
    @patch("nephos.fabric.utils.rand_string")
    def test_credentials_secret_again(
        self, mock_rand_string, mock_secret_create, mock_secret_read
    ):
        mock_secret_read.side_effect = [self.SECRET_DATA]
        credentials_secret("a-secret", "a-namespace", "a-user", "a-password")
        mock_secret_read.assert_called_once_with("a-secret", "a-namespace")
        mock_rand_string.assert_not_called()
        mock_secret_create.assert_not_called()

    @patch("nephos.fabric.utils.secret_read")
    @patch("nephos.fabric.utils.secret_create")
    @patch("nephos.fabric.utils.rand_string")
    def test_credentials_secret_badpassword(
        self, mock_rand_string, mock_secret_create, mock_secret_read
    ):
        mock_secret_read.side_effect = [self.SECRET_DATA]
        with pytest.raises(AssertionError):
            credentials_secret("a-secret", "a-namespace", "a-user", "another-password")
        mock_secret_read.assert_called_once_with("a-secret", "a-namespace")
        mock_rand_string.assert_not_called()
        mock_secret_create.assert_not_called()

    @patch("nephos.fabric.utils.secret_read")
    @patch("nephos.fabric.utils.secret_create")
    @patch("nephos.fabric.utils.rand_string")
    def test_credentials_secret_baduser(
        self, mock_rand_string, mock_secret_create, mock_secret_read
    ):
        mock_secret_read.side_effect = [self.SECRET_DATA]
        with pytest.raises(AssertionError):
            credentials_secret("a-secret", "a-namespace", "another-user", "a-password")
        mock_secret_read.assert_called_once_with("a-secret", "a-namespace")
        mock_rand_string.assert_not_called()
        mock_secret_create.assert_not_called()


class TestCryptoSecret:
    @patch("nephos.fabric.utils.secret_from_file")
    @patch("nephos.fabric.utils.glob")
    def test_crypto_secret(self, mock_glob, mock_secret_from_file):
        mock_glob.side_effect = [["./a_path/a_file.txt"]]
        crypto_secret("a-secret", "a-namespace", "./a_dir", "some_file.txt")
        mock_glob.assert_called_once_with("./a_dir/*")
        mock_secret_from_file.assert_called_once_with(
            secret="a-secret",
            namespace="a-namespace",
            key="some_file.txt",
            filename="./a_path/a_file.txt",
        )

    @patch("nephos.fabric.utils.secret_from_file")
    @patch("nephos.fabric.utils.glob")
    def test_crypto_secret_fail(self, mock_glob, mock_secret_from_file):
        mock_glob.side_effect = [[]]
        with pytest.raises(Exception):
            crypto_secret("a-secret", "a-namespace", "./a_dir", "some_file.txt")
        mock_glob.assert_called_once_with("./a_dir/*")
        mock_secret_from_file.assert_not_called()


class TestGetPod:
    @patch("nephos.fabric.utils.Executer")
    @patch("nephos.fabric.utils.execute")
    def test_get_pod(self, mock_execute, mock_Executer):
        mock_execute.side_effect = [("a-pod", None)]
        get_pod("a-namespace", "an-identifier")
        mock_execute.assert_called_once_with(
            "kubectl get pods -n a-namespace an-identifier "
            + '-o jsonpath="{.items[0].metadata.name}"'
        )
        mock_Executer.assert_called_once_with("a-pod", namespace="a-namespace")

    @patch("nephos.fabric.utils.Executer")
    @patch("nephos.fabric.utils.execute")
    def test_get_pod_fail(self, mock_execute, mock_Executer):
        mock_execute.side_effect = [(None, "error")]
        with pytest.raises(ValueError):
            get_pod("a-namespace", "an-identifier", item=3)
        mock_execute.assert_called_once_with(
            "kubectl get pods -n a-namespace an-identifier "
            + '-o jsonpath="{.items[3].metadata.name}"'
        )
        mock_Executer.assert_not_called()


class TestGetHelmPod:
    @patch("nephos.fabric.utils.get_pod")
    def test_get_helm_pod(self, mock_get_pod):
        get_helm_pod("a-namespace", "a-release", "an-app", item=7)
        mock_get_pod.assert_called_once_with(
            "a-namespace", '-l "app=an-app,release=a-release"', item=7
        )


class TestGetOrderers:
    OPTS = {
        "msps": {
            "AlphaMSP": {
                "namespace": "alpha-namespace",
                "orderers": {"nodes": {"ord1": {}, "ord2": {}}},
            },
            "BetaMSP": {"namespace": "beta-namespace"},
        }
    }

    def test_get_orderers(self):
        assert {"ord2", "ord1"} == get_orderers(opts=self.OPTS, msp="AlphaMSP")

    def test_get_orderers_from_msp_with_no_orderer(self):
        assert [] == get_orderers(opts=self.OPTS, msp="BetaMSP")


class TestGetPeers:
    OPTS = {
        "msps": {
            "BetaMSP": {
                "namespace": "peer-namespace",
                "peers": {"nodes": {"peer0": {}, "peer1": {}}},
            }
        }
    }

    def test_get_peers(self):
        assert {"peer0", "peer1"} == get_peers(opts=self.OPTS, msp="BetaMSP")


class TestGetMSPS:
    OPTS = {"msps": {"BetaMSP": {}, "AlphaMSP": {}}}

    def test_get_msps(self):
        assert {"BetaMSP", "AlphaMSP"} == get_msps(opts=self.OPTS)


class TestGetChannels:
    OPTS = {"channels": {"AChannel": {}, "BChannel": {}}}

    def test_get_channels(self):
        assert {"AChannel", "BChannel"} == get_channels(opts=self.OPTS)


class TestGetSecretGenesis:
    OPTS = {"ordering": {"secret_genesis": "secret"}}

    def test_get_secret_genesis(self):
        assert "secret" == get_secret_genesis(opts=self.OPTS)


class TestGetKafkaConfigs:
    OPTS = {"ordering": {"kafka": {"name": "kafka-hlf"}}}

    def test_get_kafka_configs(self):
        assert {"name": "kafka-hlf"} == get_kafka_configs(opts=self.OPTS)


class TestGetAnOrdererMSP:
    OPTS = {
        "msps": {
            "AlphaMSP": {"orderers": {"nodes": {"ord0": {}}}},
            "BetaMSP": {"orderers": {}},
        }
    }

    def test_get_an_orderer_msp(self):
        assert "AlphaMSP" == get_an_orderer_msp(opts=self.OPTS)


class TestIsOrdererMSP:
    OPTS = {
        "msps": {
            "AlphaMSP": {"orderers": {"nodes": {"ord0": {}}}},
            "BetaMSP": {"orderers": {}},
        }
    }

    def test_is_orderer_msp(self):
        assert is_orderer_msp(msp="AlphaMSP", opts=self.OPTS)
        assert not is_orderer_msp(msp="BetaMSP", opts=self.OPTS)


class TestGetOrgTLSCACert:
    OPTS = {
        "core": {"dir_crypto": "./crypto"},
        "ordering": {
            "tls": {
                "enable": "true",
                "tls_ca": "ca-tls"
            },
        }
    }

    @patch("nephos.fabric.utils.glob")
    def test_get_org_tls_cacert(self, mock_glob):
        mock_glob.side_effect = [["./crypto/tlscacerts/ca.crt"]]
        get_org_tls_ca_cert(self.OPTS, "ns")
        mock_glob.assert_called_once_with("./crypto/tlscacerts/*.crt")

    @patch("nephos.fabric.utils.glob")
    def test_get_org_tls_cacert_with_exception(self, mock_glob):
        mock_glob.side_effect = [["./crypto/tlscacerts/ca.crt", "./crypto/tlscacerts/ca-tls.crt"]]
        with pytest.raises(ValueError):
            get_org_tls_ca_cert(self.OPTS, "ns")
        mock_glob.assert_called_once_with("./crypto/tlscacerts/*.crt")

    @patch("nephos.fabric.utils.glob")
    def test_get_org_tls_cacert_cryptogen(self, mock_glob):
        opts = deepcopy(self.OPTS)
        opts["ordering"]["tls"] = {
            "enable" : "true"
        }
        mock_glob.side_effect = [["./crypto/crypto-config/*Organizations/ns_TLS/tlsca/ca.pem"]]
        get_org_tls_ca_cert(opts, "ns")
        mock_glob.assert_called_once_with("./crypto/crypto-config/*Organizations/ns*/tlsca/*.pem")


class TestIsOrdererTLSTrue:
    OPTS = {
        "ordering": {
            "tls": {
                "enable": "true",
                "tls_ca": "ca-tls"
            },
        }
    }

    def test_is_orderer_tls_true(self):
        assert is_orderer_tls_true(opts=self.OPTS)

    def test_is_orderer_tls_true_tls_false(self):
        opts = deepcopy(self.OPTS)
        opts["ordering"]["tls"] = {
            "enable": "false"
        }
        assert not is_orderer_tls_true(opts=opts)

    def test_is_orderer_tls_true_tls_false(self):
        opts = deepcopy(self.OPTS)
        opts["ordering"] = {}
        assert not is_orderer_tls_true(opts=opts)


class TestGetTLSPath:
    OPTS = {
        "core": {"dir_crypto": "./crypto"},
        "ordering": {
            "tls": {
                "enable": "true",
                "tls_ca": "ca-tls"
            },
        }
    }

    @patch("nephos.fabric.utils.glob")
    def test_get_tls_path(self, mock_glob):
        mock_glob.side_effect = [["/crypto/ord0_TLS/tls"]]
        get_tls_path(self.OPTS, "orderer", "ns", "ord0")
        mock_glob.assert_called_once_with("./crypto/ord0_TLS/tls")

    @patch("nephos.fabric.utils.glob")
    def test_get_tls_path_with_exception(self, mock_glob):
        mock_glob.side_effect = [["/crypto/ord0_TLS/tls", "/crypto/ord1_TLS/tls"]]
        with pytest.raises(ValueError):
            get_tls_path(self.OPTS, "orderer", "ns", "ord0")
        mock_glob.assert_called_once_with("./crypto/ord0_TLS/tls")

    @patch("nephos.fabric.utils.glob")
    def test_get_tls_path_cryptogen(self, mock_glob):
        opts = deepcopy(self.OPTS)
        opts["ordering"]["tls"] = {
            "enable" : "true"
        }
        mock_glob.side_effect = [["./crypto/crypto-config/ordererOrganizations/ns_MSP/orderers/ord0/tls"]]
        get_tls_path(opts, "orderer", "ns", "ord0")
        mock_glob.assert_called_once_with("./crypto/crypto-config/ordererOrganizations/ns*/orderers/ord0*/tls")


class TestRenameFile:
    @patch("nephos.fabric.utils.rename")
    @patch("nephos.fabric.utils.glob")
    def test_rename_file(self, mock_glob, mock_rename):
        mock_glob.side_effect = [["directory/abc"]]
        rename_file("directory", "name")
        mock_glob.assert_called_once_with("directory/*")
        mock_rename.assert_called_once_with("directory/abc", "directory/name")

    @patch("nephos.fabric.utils.glob")
    def test_rename_file_with_exception(self, mock_glob):
        mock_glob.side_effect = [["directory/abc", "directory/xyz"]]
        with pytest.raises(ValueError):
            rename_file("directory", "name")
        mock_glob.assert_called_once_with("directory/*")