from copy import deepcopy
from unittest.mock import call, patch, Mock

import pytest

from nephos.fabric.crypto import (
    CryptoInfo,
    check_id,
    register_id,
    enroll_id,
    create_admin,
    admin_creds,
    copy_secret,
    msp_secrets,
    admin_msp,
    item_to_secret,
    id_to_secrets,
    cacerts_to_secrets,
    setup_id,
    setup_nodes,
    genesis_block,
    channel_tx,
    PWD,
)


class TestChechId:
    @patch("nephos.fabric.crypto.sleep")
    @patch("nephos.fabric.crypto.get_pod")
    def test_check_id(self, mock_get_pod, mock_sleep):
        mock_executor = Mock()
        mock_get_pod.side_effect = [mock_executor]
        mock_executor.execute.side_effect = [
            (None, "no rows in result set")  # List identities
        ]
        check_id("a-namespace", "a-ca", "an-ord")
        mock_get_pod.assert_called_once_with(
            namespace="a-namespace", release="a-ca", app="hlf-ca", verbose=False
        )
        mock_executor.execute.assert_called_once_with(
            "fabric-ca-client identity list --id an-ord"
        )
        mock_sleep.assert_not_called()

    @patch("nephos.fabric.crypto.sleep")
    @patch("nephos.fabric.crypto.get_pod")
    def test_check_id_again(self, mock_get_pod, mock_sleep):
        mock_executor = Mock()
        mock_get_pod.side_effect = [mock_executor]
        mock_executor.execute.side_effect = [("an-ord", None)]  # List identities
        check_id("a-namespace", "a-ca", "an-ord", verbose=True)
        mock_get_pod.assert_called_once_with(
            namespace="a-namespace", release="a-ca", app="hlf-ca", verbose=True
        )
        mock_executor.execute.assert_called_once_with(
            "fabric-ca-client identity list --id an-ord"
        )
        mock_sleep.assert_not_called()

    @patch("nephos.fabric.crypto.sleep")
    @patch("nephos.fabric.crypto.get_pod")
    def test_check_id_serverconnection(self, mock_get_pod, mock_sleep):
        mock_executor = Mock()
        mock_get_pod.side_effect = [mock_executor]
        mock_executor.execute.side_effect = [
            (None, "could not connect to server"),  # List identities
            (None, "no rows in result set"),  # List identities
        ]
        check_id("a-namespace", "a-ca", "an-ord", verbose=False)
        mock_get_pod.assert_called_once_with(
            namespace="a-namespace", release="a-ca", app="hlf-ca", verbose=False
        )
        mock_executor.execute.assert_has_calls(
            [
                call("fabric-ca-client identity list --id an-ord"),
                call("fabric-ca-client identity list --id an-ord"),
            ]
        )
        mock_sleep.assert_called_once_with(15)

    @patch("nephos.fabric.crypto.sleep")
    @patch("nephos.fabric.crypto.get_pod")
    def test_check_id_admin(self, mock_get_pod, mock_sleep):
        mock_executor = Mock()
        mock_get_pod.side_effect = [mock_executor]
        mock_executor.execute.side_effect = [
            (None, "no rows in result set")  # List identities
        ]
        check_id("a-namespace", "a-ca", "an-admin")
        mock_get_pod.assert_called_once_with(
            namespace="a-namespace", release="a-ca", app="hlf-ca", verbose=False
        )
        mock_executor.execute.assert_called_once_with(
            "fabric-ca-client identity list --id an-admin"
        )
        mock_sleep.assert_not_called()


class TestRegisterId:
    @patch("nephos.fabric.crypto.sleep")
    @patch("nephos.fabric.crypto.get_pod")
    @patch("nephos.fabric.crypto.check_id")
    def test_register_id(self, mock_check_id, mock_get_pod, mock_sleep):
        mock_executor = Mock()
        mock_check_id.side_effect = [False]
        mock_get_pod.side_effect = [mock_executor]
        mock_executor.execute.side_effect = [("Register", None)]  # Register identities
        register_id("a-namespace", "a-ca", "an-ord", "a-password", "orderer")
        mock_get_pod.assert_called_once_with(
            namespace="a-namespace", release="a-ca", app="hlf-ca", verbose=False
        )
        mock_executor.execute.assert_has_calls(
            [
                call(
                    "fabric-ca-client register --id.name an-ord --id.secret a-password --id.type orderer"
                )
            ]
        )
        mock_sleep.assert_not_called()

    @patch("nephos.fabric.crypto.sleep")
    @patch("nephos.fabric.crypto.get_pod")
    @patch("nephos.fabric.crypto.check_id")
    def test_register_id_again(self, mock_check_id, mock_get_pod, mock_sleep):
        mock_executor = Mock()
        mock_check_id.side_effect = [True]
        mock_get_pod.side_effect = [mock_executor]
        register_id(
            "a-namespace", "a-ca", "an-ord", "a-password", "orderer", verbose=True
        )
        mock_get_pod.assert_called_once_with(
            namespace="a-namespace", release="a-ca", app="hlf-ca", verbose=True
        )
        mock_executor.execute.assert_not_called()
        mock_sleep.assert_not_called()

    @patch("nephos.fabric.crypto.sleep")
    @patch("nephos.fabric.crypto.get_pod")
    @patch("nephos.fabric.crypto.check_id")
    def test_register_id_error(self, mock_check_id, mock_get_pod, mock_sleep):
        mock_executor = Mock()
        mock_check_id.side_effect = [False]
        mock_get_pod.side_effect = [mock_executor]
        mock_executor.execute.side_effect = [
            (None, "connection error"),  # Error registering identities
            ("Register", None),  # Register identities
        ]
        register_id("a-namespace", "a-ca", "an-ord", "a-password", "orderer")
        mock_get_pod.assert_called_once_with(
            namespace="a-namespace", release="a-ca", app="hlf-ca", verbose=False
        )
        mock_executor.execute.assert_has_calls(
            [
                call(
                    "fabric-ca-client register --id.name an-ord --id.secret a-password --id.type orderer"
                ),
                call(
                    "fabric-ca-client register --id.name an-ord --id.secret a-password --id.type orderer"
                ),
            ]
        )
        mock_sleep.assert_called_once_with(15)

    @patch("nephos.fabric.crypto.sleep")
    @patch("nephos.fabric.crypto.get_pod")
    @patch("nephos.fabric.crypto.check_id")
    def test_register_id_admin(self, mock_check_id, mock_get_pod, mock_sleep):
        mock_executor = Mock()
        mock_check_id.side_effect = [False]
        mock_get_pod.side_effect = [mock_executor]
        mock_executor.execute.side_effect = [("Register", None)]  # Register identities
        register_id("a-namespace", "a-ca", "an-admin", "a-password", admin=True)
        mock_get_pod.assert_called_once_with(
            namespace="a-namespace", release="a-ca", app="hlf-ca", verbose=False
        )
        mock_executor.execute.assert_called_once_with(
            "fabric-ca-client register --id.name an-admin --id.secret a-password --id.type client"
            + " --id.attrs 'admin=true:ecert'"
        )
        mock_sleep.assert_not_called()


class TestEnrollId:
    OPTS = {
        "core": {"dir_crypto": "./crypto"},
        "cas": {"a-ca": {"namespace": "ca-namespace", "tls_cert": "./tls_cert.pem"}},
    }

    @patch("nephos.fabric.crypto.isdir")
    @patch("nephos.fabric.crypto.ingress_read")
    @patch("nephos.fabric.crypto.execute_until_success")
    @patch("nephos.fabric.crypto.abspath")
    def test_enroll_id(
        self, mock_abspath, mock_execute_until_success, mock_ingress_read, mock_isdir
    ):
        mock_ingress_read.side_effect = [["an-ingress"]]
        mock_isdir.side_effect = [False]
        mock_abspath.side_effect = ["/home/nephos/tls_cert.pem"]
        enroll_id(self.OPTS, "a-ca", "an-ord", "a-password")
        mock_ingress_read.assert_called_once_with(
            "a-ca-hlf-ca", namespace="ca-namespace", verbose=False
        )
        mock_abspath.assert_called_once_with("./tls_cert.pem")
        mock_isdir.assert_called_once_with("./crypto/an-ord_MSP")
        mock_execute_until_success.assert_called_once_with(
            "FABRIC_CA_CLIENT_HOME=./crypto fabric-ca-client enroll "
            + "-u https://an-ord:a-password@an-ingress -M ./crypto/an-ord_MSP "
            + "--tls.certfiles /home/nephos/tls_cert.pem"
        )

    @patch("nephos.fabric.crypto.isdir")
    @patch("nephos.fabric.crypto.ingress_read")
    @patch("nephos.fabric.crypto.execute_until_success")
    @patch("nephos.fabric.crypto.abspath")
    def test_enroll_id_again(
        self, mock_abspath, mock_execute_until_success, mock_ingress_read, mock_isdir
    ):
        mock_ingress_read.side_effect = [["an-ingress"]]
        mock_isdir.side_effect = [True]
        mock_abspath.side_effect = ["/home/nephos/tls_cert.pem"]
        enroll_id(self.OPTS, "a-ca", "a-peer", "a-password")
        mock_ingress_read.assert_called_once_with(
            "a-ca-hlf-ca", namespace="ca-namespace", verbose=False
        )
        mock_isdir.assert_called_once_with("./crypto/a-peer_MSP")
        mock_execute_until_success.assert_not_called()

    @patch("nephos.fabric.crypto.isdir")
    @patch("nephos.fabric.crypto.ingress_read")
    @patch("nephos.fabric.crypto.execute_until_success")
    @patch("nephos.fabric.crypto.abspath")
    def test_enroll_verbose(
        self, mock_abspath, mock_execute_until_success, mock_ingress_read, mock_isdir
    ):
        mock_ingress_read.side_effect = [["an-ingress"]]
        mock_isdir.side_effect = [False]
        mock_abspath.side_effect = ["/home/nephos/tls_cert.pem"]
        enroll_id(self.OPTS, "a-ca", "a-peer", "a-password", verbose=True)
        mock_ingress_read.assert_called_once_with(
            "a-ca-hlf-ca", namespace="ca-namespace", verbose=True
        )
        mock_isdir.assert_called_once_with("./crypto/a-peer_MSP")
        mock_execute_until_success.assert_called_once_with(
            "FABRIC_CA_CLIENT_HOME=./crypto fabric-ca-client enroll "
            + "-u https://a-peer:a-password@an-ingress -M ./crypto/a-peer_MSP "
            + "--tls.certfiles /home/nephos/tls_cert.pem"
        )


class TestCreateAdmin:
    OPTS = {
        "core": {"dir_config": "./config", "dir_crypto": "./crypto"},
        "msps": {
            "a_MSP": {
                "ca": "a-ca",
                "org_admin": "an_admin",
                "org_adminpw": "a_password",
            }
        },
        "cas": {"a-ca": {"namespace": "ca-namespace", "tls_cert": "./tls_cert.pem"}},
    }

    @patch("nephos.fabric.crypto.register_id")
    @patch("nephos.fabric.crypto.listdir")
    @patch("nephos.fabric.crypto.isdir")
    @patch("nephos.fabric.crypto.ingress_read")
    @patch("nephos.fabric.crypto.execute")
    @patch("nephos.fabric.crypto.abspath")
    def test_ca_create_admin(
        self,
        mock_abspath,
        mock_execute,
        mock_ingress_read,
        mock_isdir,
        mock_listdir,
        mock_register_id,
    ):
        mock_isdir.side_effect = [False]
        mock_listdir.side_effect = [False]
        mock_ingress_read.side_effect = [["an-ingress"]]
        mock_abspath.side_effect = ["/home/nephos/tls_cert.pem"]
        create_admin(self.OPTS, "a_MSP")
        mock_ingress_read.assert_called_once_with(
            "a-ca-hlf-ca", namespace="ca-namespace", verbose=False
        )
        mock_register_id.assert_called_once_with(
            "ca-namespace", "a-ca", "an_admin", "a_password", admin=True, verbose=False
        )
        mock_isdir.assert_called_once_with("./crypto/a_MSP/keystore")
        mock_listdir.assert_not_called()
        mock_abspath.assert_called_once_with("./tls_cert.pem")
        mock_execute.assert_called_once_with(
            "FABRIC_CA_CLIENT_HOME=./config fabric-ca-client enroll "
            + "-u https://an_admin:a_password@an-ingress -M ./crypto/a_MSP --tls.certfiles /home/nephos/tls_cert.pem",
            verbose=False,
        )

    @patch("nephos.fabric.crypto.register_id")
    @patch("nephos.fabric.crypto.listdir")
    @patch("nephos.fabric.crypto.isdir")
    @patch("nephos.fabric.crypto.ingress_read")
    @patch("nephos.fabric.crypto.execute")
    @patch("nephos.fabric.crypto.abspath")
    def test_ca_create_admin_again(
        self,
        mock_abspath,
        mock_execute,
        mock_ingress_read,
        mock_isdir,
        mock_listdir,
        mock_register_id,
    ):
        mock_isdir.side_effect = [True]
        mock_listdir.side_effect = [True]
        mock_ingress_read.side_effect = [["an-ingress"]]
        mock_abspath.side_effect = ["/home/nephos/tls_cert.pem"]
        create_admin(self.OPTS, "a_MSP", verbose=True)
        mock_ingress_read.assert_called_once_with(
            "a-ca-hlf-ca", namespace="ca-namespace", verbose=True
        )
        mock_register_id.assert_called_once_with(
            "ca-namespace", "a-ca", "an_admin", "a_password", admin=True, verbose=True
        )
        mock_isdir.assert_called_once_with("./crypto/a_MSP/keystore")
        mock_listdir.assert_called_once_with("./crypto/a_MSP/keystore")
        mock_abspath.assert_not_called()
        mock_execute.assert_not_called()


class TestAdminCreds:
    OPTS = {"msps": {"an-msp": {"namespace": "msp-ns", "org_admin": "an-admin"}}}

    @patch("nephos.fabric.crypto.credentials_secret")
    def test_admin_creds(self, mock_credentials_secret):
        mock_credentials_secret.side_effect = [{"CA_PASSWORD": "a_password"}]
        admin_creds(self.OPTS, "an-msp")
        mock_credentials_secret.assert_called_once_with(
            "hlf--an-admin-admincred",
            "msp-ns",
            username="an-admin",
            password=None,
            verbose=False,
        )
        assert self.OPTS["msps"]["an-msp"].get("org_adminpw") == "a_password"

    @patch("nephos.fabric.crypto.credentials_secret")
    def test_admin_creds_again(self, mock_credentials_secret):
        mock_credentials_secret.side_effect = [{"CA_PASSWORD": "a_password"}]
        admin_creds(self.OPTS, "an-msp", verbose=True)
        mock_credentials_secret.assert_called_once_with(
            "hlf--an-admin-admincred",
            "msp-ns",
            username="an-admin",
            password="a_password",
            verbose=True,
        )
        assert self.OPTS["msps"]["an-msp"].get("org_adminpw") == "a_password"


class TestCopySecret:
    @patch("nephos.fabric.crypto.shutil")
    @patch("nephos.fabric.crypto.makedirs")
    @patch("nephos.fabric.crypto.isfile")
    @patch("nephos.fabric.crypto.isdir")
    @patch("nephos.fabric.crypto.glob")
    def test_copy_secret(
        self, mock_glob, mock_isdir, mock_isfile, mock_makedirs, mock_shutil
    ):
        mock_glob.side_effect = [["./a_dir/a_MSP/signcerts/cert.pem"]]
        mock_isfile.side_effect = [False]
        mock_isdir.side_effect = [False]
        copy_secret("./a_dir/a_MSP/signcerts", "./a_dir/a_MSP/admincerts")
        mock_glob.assert_called_once_with("./a_dir/a_MSP/signcerts/*")
        mock_isfile.assert_called_once_with("./a_dir/a_MSP/admincerts/cert.pem")
        mock_isdir.assert_called_once_with("./a_dir/a_MSP/admincerts")
        mock_makedirs.assert_called_once_with("./a_dir/a_MSP/admincerts")
        mock_shutil.copy.assert_called_once_with(
            "./a_dir/a_MSP/signcerts/cert.pem", "./a_dir/a_MSP/admincerts/cert.pem"
        )

    @patch("nephos.fabric.crypto.shutil")
    @patch("nephos.fabric.crypto.makedirs")
    @patch("nephos.fabric.crypto.isfile")
    @patch("nephos.fabric.crypto.isdir")
    @patch("nephos.fabric.crypto.glob")
    def test_copy_secret_again(
        self, mock_glob, mock_isdir, mock_isfile, mock_makedirs, mock_shutil
    ):
        mock_glob.side_effect = [["./a_dir/a_MSP/signcerts/cert.pem"]]
        mock_isfile.side_effect = [True]
        copy_secret("./a_dir/a_MSP/signcerts", "./a_dir/a_MSP/admincerts")
        mock_glob.assert_called_once_with("./a_dir/a_MSP/signcerts/*")
        mock_isfile.assert_called_once_with("./a_dir/a_MSP/admincerts/cert.pem")
        mock_isdir.assert_not_called()
        mock_makedirs.assert_not_called()
        mock_shutil.copy.assert_not_called()

    @patch("nephos.fabric.crypto.shutil")
    @patch("nephos.fabric.crypto.makedirs")
    @patch("nephos.fabric.crypto.isfile")
    @patch("nephos.fabric.crypto.isdir")
    @patch("nephos.fabric.crypto.glob")
    def test_copy_secret_fail(
        self, mock_glob, mock_isdir, mock_isfile, mock_makedirs, mock_shutil
    ):
        mock_glob.side_effect = [[]]
        with pytest.raises(ValueError):
            copy_secret("./a_dir/a_MSP/signcerts", "./a_dir/a_MSP/admincerts")
        mock_glob.assert_called_once_with("./a_dir/a_MSP/signcerts/*")
        mock_isfile.assert_not_called()
        mock_isdir.assert_not_called()
        mock_makedirs.assert_not_called()
        mock_shutil.copy.assert_not_called()


# TODO: Add verbose test
class TestMspSecrets:
    OPTS = {
        "core": {"dir_crypto": "./crypto"},
        "cas": {"a-ca": {}},
        "msps": {
            "a_MSP": {"namespace": "msp-ns", "org_admin": "an-admin", "ca": "a-ca"}
        },
    }

    @patch("nephos.fabric.crypto.id_to_secrets")
    @patch("nephos.fabric.crypto.glob")
    @patch("nephos.fabric.crypto.copy_secret")
    @patch("nephos.fabric.crypto.cacerts_to_secrets")
    def test_msp_secrets(
        self, mock_cacerts_to_secrets, mock_copy_secret, mock_glob, mock_id_to_secrets
    ):
        opts = deepcopy(self.OPTS)
        msp_secrets(opts, "a_MSP")
        mock_glob.assert_not_called()
        mock_copy_secret.assert_called_once_with(
            "./crypto/a_MSP/signcerts", "./crypto/a_MSP/admincerts"
        )
        mock_cacerts_to_secrets.assert_called_once_with(
            "msp-ns", "./crypto/a_MSP", "an-admin", verbose=False
        )
        mock_id_to_secrets.assert_called_once_with(
            "msp-ns", "./crypto/a_MSP", "an-admin", verbose=False
        )

    @patch("nephos.fabric.crypto.id_to_secrets")
    @patch("nephos.fabric.crypto.glob")
    @patch("nephos.fabric.crypto.copy_secret")
    @patch("nephos.fabric.crypto.cacerts_to_secrets")
    def test_msp_secrets_cryptogen(
        self, mock_cacerts_to_secrets, mock_copy_secret, mock_glob, mock_id_to_secrets
    ):
        mock_glob.side_effect = [
            [
                "./crypto/crypto-config/ordererOrganizations/msp-ns.domain/users/Admin@msp-ns.domain/msp"
            ]
        ]
        opts = deepcopy(self.OPTS)
        opts["cas"] = {}
        msp_secrets(opts, "a_MSP")
        mock_glob.assert_called_once_with(
            "./crypto/crypto-config/*Organizations/msp-ns*/users/Admin*/msp"
        )
        mock_copy_secret.assert_called_once_with(
            "./crypto/crypto-config/ordererOrganizations/msp-ns.domain/users/Admin@msp-ns.domain/msp/signcerts",
            "./crypto/crypto-config/ordererOrganizations/msp-ns.domain/users/Admin@msp-ns.domain/msp/admincerts",
        )
        mock_cacerts_to_secrets.assert_called_once_with(
            "msp-ns",
            "./crypto/crypto-config/ordererOrganizations/msp-ns.domain/users/Admin@msp-ns.domain/msp",
            "an-admin",
            verbose=False,
        )
        mock_id_to_secrets.assert_called_once_with(
            "msp-ns",
            "./crypto/crypto-config/ordererOrganizations/msp-ns.domain/users/Admin@msp-ns.domain/msp",
            "an-admin",
            verbose=False,
        )

    @patch("nephos.fabric.crypto.id_to_secrets")
    @patch("nephos.fabric.crypto.glob")
    @patch("nephos.fabric.crypto.copy_secret")
    @patch("nephos.fabric.crypto.cacerts_to_secrets")
    def test_msp_secrets_cryptogen_fail(
        self, mock_cacerts_to_secrets, mock_copy_secret, mock_glob, mock_id_to_secrets
    ):
        mock_glob.side_effect = [
            [
                "./crypto/crypto-config/ordererOrganizations/msp-ns.domain/users/Admin@msp-ns.domain/msp",
                "./crypto/crypto-config/peerOrganizations/msp-ns.domain/users/Admin@msp-ns.domain/msp",
            ]
        ]
        opts = deepcopy(self.OPTS)
        opts["cas"] = {}
        with pytest.raises(ValueError):
            msp_secrets(opts, "a_MSP")
        mock_glob.assert_called_once_with(
            "./crypto/crypto-config/*Organizations/msp-ns*/users/Admin*/msp"
        )
        mock_copy_secret.assert_not_called()
        mock_cacerts_to_secrets.assert_not_called()
        mock_id_to_secrets.assert_not_called()


# TODO: Add verbosity test
class TestAdminMsp:
    OPTS = {
        "core": {"dir_config": "./a-dir"},
        "cas": {"a-ca": {}},
        "msps": {
            "an-msp": {"namespace": "msp-ns", "ca": "a-ca", "org_admin": "an_admin"}
        },
    }

    @patch("nephos.fabric.crypto.ns_create")
    @patch("nephos.fabric.crypto.msp_secrets")
    @patch("nephos.fabric.crypto.create_admin")
    @patch("nephos.fabric.crypto.admin_creds")
    def test_admin_msp(
        self, mock_ca_creds, mock_create_admin, mock_msp_secrets, mock_ns_create
    ):
        opts = deepcopy(self.OPTS)
        admin_msp(opts, "an-msp")
        mock_ns_create.assert_called_once_with("msp-ns", verbose=False)
        mock_ca_creds.assert_called_once_with(opts, "an-msp", verbose=False)
        mock_create_admin.assert_called_once_with(opts, "an-msp", verbose=False)
        mock_msp_secrets.assert_called_once_with(opts, "an-msp", verbose=False)

    @patch("nephos.fabric.crypto.ns_create")
    @patch("nephos.fabric.crypto.msp_secrets")
    @patch("nephos.fabric.crypto.create_admin")
    @patch("nephos.fabric.crypto.admin_creds")
    def test_admin_msp_cryptogen(
        self, mock_ca_creds, mock_create_admin, mock_msp_secrets, mock_ns_create
    ):
        opts = deepcopy(self.OPTS)
        opts["cas"] = {}
        admin_msp(opts, "an-msp")
        mock_ns_create.assert_called_once_with("msp-ns", verbose=False)
        mock_ca_creds.assert_not_called()
        mock_create_admin.assert_not_called()
        mock_msp_secrets.assert_called_once_with(opts, "an-msp", verbose=False)


class TestItemToSecret:
    @patch("nephos.fabric.crypto.print")
    @patch("nephos.fabric.crypto.crypto_secret")
    def test_item_to_secret(self, mock_crypto_secret, mock_print):
        item_to_secret(
            "msp-ns",
            "./crypto",
            "a-user",
            CryptoInfo("a-type", "a_subfolder", "a-key", True),
        )
        mock_crypto_secret.assert_called_once_with(
            "hlf--a-user-a-type",
            "msp-ns",
            file_path="./crypto/a_subfolder",
            key="a-key",
            verbose=False,
        )
        mock_print.assert_not_called()

    @patch("nephos.fabric.crypto.print")
    @patch("nephos.fabric.crypto.crypto_secret")
    def test_item_to_secret_unrequired(self, mock_crypto_secret, mock_print):
        mock_crypto_secret.side_effect = [Exception()]
        item_to_secret(
            "msp-ns",
            "./crypto",
            "a-user",
            CryptoInfo("a-type", "a_subfolder", "a-key", False),
        )
        mock_crypto_secret.assert_called_once_with(
            "hlf--a-user-a-type",
            "msp-ns",
            file_path="./crypto/a_subfolder",
            key="a-key",
            verbose=False,
        )
        mock_print.assert_called_once_with(
            'No ./crypto/a_subfolder found, so secret "hlf--a-user-a-type" was not created'
        )

    @patch("nephos.fabric.crypto.print")
    @patch("nephos.fabric.crypto.crypto_secret")
    def test_item_to_secret_failed(self, mock_crypto_secret, mock_print):
        mock_crypto_secret.side_effect = [Exception()]
        with pytest.raises(Exception):
            item_to_secret(
                "msp-ns",
                "./crypto",
                "a-user",
                CryptoInfo("a-type", "a_subfolder", "a-key", True),
            )
        mock_crypto_secret.assert_called_once_with(
            "hlf--a-user-a-type",
            "msp-ns",
            file_path="./crypto/a_subfolder",
            key="a-key",
            verbose=False,
        )
        mock_print.assert_not_called()


class TestIdToSecrets:
    @patch("nephos.fabric.crypto.item_to_secret")
    def test_id_to_secrets(self, mock_item_to_secret):
        mock_item_to_secret.side_effect = [None, None]
        id_to_secrets("msp-ns", "./crypto", "a-user")
        mock_item_to_secret.assert_has_calls(
            [
                call(
                    "msp-ns",
                    "./crypto",
                    "a-user",
                    CryptoInfo("idcert", "signcerts", "cert.pem", True),
                    verbose=False,
                ),
                call(
                    "msp-ns",
                    "./crypto",
                    "a-user",
                    CryptoInfo("idkey", "keystore", "key.pem", True),
                    verbose=False,
                ),
            ]
        )

    @patch("nephos.fabric.crypto.item_to_secret")
    def test_id_to_secrets_nocert(self, mock_item_to_secret):
        mock_item_to_secret.side_effect = [Exception()]
        with pytest.raises(Exception):
            id_to_secrets("msp-ns", "./crypto", "a-user", verbose=True)
        mock_item_to_secret.assert_called_once_with(
            "msp-ns",
            "./crypto",
            "a-user",
            CryptoInfo("idcert", "signcerts", "cert.pem", True),
            verbose=True,
        )


class TestCaCertsToSecrets:
    @patch("nephos.fabric.crypto.item_to_secret")
    def test_cacerts_to_secrets(self, mock_item_to_secret):
        mock_item_to_secret.side_effect = [None, None]
        cacerts_to_secrets("msp-ns", "./crypto", "a-user")
        mock_item_to_secret.assert_has_calls(
            [
                call(
                    "msp-ns",
                    "./crypto",
                    "a-user",
                    CryptoInfo("cacert", "cacerts", "cacert.pem", True),
                    verbose=False,
                ),
                call(
                    "msp-ns",
                    "./crypto",
                    "a-user",
                    CryptoInfo(
                        "caintcert",
                        "intermediatecerts",
                        "intermediatecacert.pem",
                        False,
                    ),
                    verbose=False,
                ),
            ]
        )

    @patch("nephos.fabric.crypto.item_to_secret")
    def test_cacerts_to_secrets_nocacert(self, mock_item_to_secret):
        mock_item_to_secret.side_effect = [Exception()]
        with pytest.raises(Exception):
            cacerts_to_secrets("msp-ns", "./crypto", "a-user")
        mock_item_to_secret.assert_called_once_with(
            "msp-ns",
            "./crypto",
            "a-user",
            CryptoInfo("cacert", "cacerts", "cacert.pem", True),
            verbose=False,
        )


class TestSetupId:
    OPTS = {
        "core": {"dir_crypto": "./crypto"},
        "cas": {
            "ca-ord": {"namespace": "ca-namespace"},
            "ca-peer": {"namespace": "ca-namespace"},
        },
        "msps": {
            "ord_MSP": {"ca": "ca-ord", "namespace": "ord-ns"},
            "peer_MSP": {"ca": "ca-peer", "namespace": "peer-ns"},
        },
        "peers": {"names": ["peer0"], "msp": "peer_MSP"},
        "orderers": {"names": ["ord0"], "msp": "ord_MSP"},
    }

    @patch("nephos.fabric.crypto.register_id")
    @patch("nephos.fabric.crypto.enroll_id")
    @patch("nephos.fabric.crypto.id_to_secrets")
    @patch("nephos.fabric.crypto.glob")
    @patch("nephos.fabric.crypto.credentials_secret")
    def test_setup_id(
        self,
        mock_credentials_secret,
        mock_glob,
        mock_id_to_secrets,
        mock_enroll_id,
        mock_register_id,
    ):
        opts = deepcopy(self.OPTS)
        mock_credentials_secret.side_effect = [
            {"CA_USERNAME": "peer0", "CA_PASSWORD": "peer0-pw"}
        ]
        mock_enroll_id.side_effect = ["./peer0_MSP"]
        setup_id(opts, "peer_MSP", "peer0", "peer")
        mock_credentials_secret.assert_called_once_with(
            "hlf--peer0-cred", "peer-ns", username="peer0", verbose=False
        )
        mock_register_id.assert_called_once_with(
            "ca-namespace", "ca-peer", "peer0", "peer0-pw", "peer", verbose=False
        )
        mock_enroll_id.assert_called_once_with(
            opts, "ca-peer", "peer0", "peer0-pw", verbose=False
        )
        mock_glob.assert_not_called()
        mock_id_to_secrets.assert_called_once_with(
            namespace="peer-ns", msp_path="./peer0_MSP", username="peer0", verbose=False
        )

    @patch("nephos.fabric.crypto.register_id")
    @patch("nephos.fabric.crypto.enroll_id")
    @patch("nephos.fabric.crypto.id_to_secrets")
    @patch("nephos.fabric.crypto.glob")
    @patch("nephos.fabric.crypto.credentials_secret")
    def test_setup_id_ord(
        self,
        mock_credentials_secret,
        mock_glob,
        mock_id_to_secrets,
        mock_enroll_id,
        mock_register_id,
    ):
        opts = deepcopy(self.OPTS)
        mock_credentials_secret.side_effect = [
            {"CA_USERNAME": "ord0", "CA_PASSWORD": "ord0-pw"}
        ]
        mock_enroll_id.side_effect = ["./ord0_MSP"]
        setup_id(opts, "ord_MSP", "ord0", "orderer")
        mock_credentials_secret.assert_called_once_with(
            "hlf--ord0-cred", "ord-ns", username="ord0", verbose=False
        )
        mock_register_id.assert_called_once_with(
            "ca-namespace", "ca-ord", "ord0", "ord0-pw", "orderer", verbose=False
        )
        mock_enroll_id.assert_called_once_with(
            opts, "ca-ord", "ord0", "ord0-pw", verbose=False
        )
        mock_glob.assert_not_called()
        mock_id_to_secrets.assert_called_once_with(
            namespace="ord-ns", msp_path="./ord0_MSP", username="ord0", verbose=False
        )

    @patch("nephos.fabric.crypto.register_id")
    @patch("nephos.fabric.crypto.enroll_id")
    @patch("nephos.fabric.crypto.id_to_secrets")
    @patch("nephos.fabric.crypto.glob")
    @patch("nephos.fabric.crypto.credentials_secret")
    def test_setup_id_cryptogen(
        self,
        mock_credentials_secret,
        mock_glob,
        mock_id_to_secrets,
        mock_enroll_id,
        mock_register_id,
    ):
        opts = deepcopy(self.OPTS)
        opts["cas"] = {}
        mock_glob.side_effect = [
            [
                "./crypto/crypto-config/peerOrganizations/peer-ns.domain/peers/peer0.domain/msp"
            ]
        ]
        setup_id(opts, "peer_MSP", "peer0", "peer")
        mock_credentials_secret.assert_not_called()
        mock_register_id.assert_not_called()
        mock_enroll_id.assert_not_called()
        mock_glob.assert_called_once_with(
            "./crypto/crypto-config/peerOrganizations/peer-ns*/peers/peer0*/msp"
        )
        mock_id_to_secrets.assert_called_once_with(
            namespace="peer-ns",
            msp_path="./crypto/crypto-config/peerOrganizations/peer-ns.domain/peers/peer0.domain/msp",
            username="peer0",
            verbose=False,
        )

    @patch("nephos.fabric.crypto.register_id")
    @patch("nephos.fabric.crypto.enroll_id")
    @patch("nephos.fabric.crypto.id_to_secrets")
    @patch("nephos.fabric.crypto.glob")
    @patch("nephos.fabric.crypto.credentials_secret")
    def test_setup_id_cryptogen_fail(
        self,
        mock_credentials_secret,
        mock_glob,
        mock_id_to_secrets,
        mock_enroll_id,
        mock_register_id,
    ):
        opts = deepcopy(self.OPTS)
        opts["cas"] = {}
        mock_glob.side_effect = [
            [
                "./crypto/crypto-config/peerOrganizations/peer-ns.domain/peers/peer0.domain/msp",
                "./crypto/crypto-config/peerOrganizations/peer-ns.domain/peers/peer0.another-domain/msp",
            ]
        ]
        with pytest.raises(ValueError):
            setup_id(opts, "peer_MSP", "peer0", "peer")
        mock_credentials_secret.assert_not_called()
        mock_register_id.assert_not_called()
        mock_enroll_id.assert_not_called()
        mock_glob.assert_called_once_with(
            "./crypto/crypto-config/peerOrganizations/peer-ns*/peers/peer0*/msp"
        )
        mock_id_to_secrets.assert_not_called()


class TestSetupNodes:
    OPTS = {
        "cas": {
            "ca-ord": {"namespace": "ca-namespace"},
            "ca-peer": {"namespace": "ca-namespace"},
        },
        "msps": {
            "ord_MSP": {"ca": "ca-ord", "namespace": "ord-ns"},
            "peer_MSP": {"ca": "ca-peer", "namespace": "peer-ns"},
        },
        "peers": {"names": ["peer0", "peer1"], "msp": "peer_MSP"},
        "orderers": {"names": ["ord0"], "msp": "ord_MSP"},
    }

    @patch("nephos.fabric.crypto.setup_id")
    def test_setup_nodes(self, mock_setup_id):
        setup_nodes(self.OPTS, "peer")
        mock_setup_id.assert_has_calls(
            [
                call(self.OPTS, "peer_MSP", "peer0", "peer", verbose=False),
                call(self.OPTS, "peer_MSP", "peer1", "peer", verbose=False),
            ]
        )

    @patch("nephos.fabric.crypto.setup_id")
    def test_setup_nodes_ord(self, mock_setup_id):
        setup_nodes(self.OPTS, "orderer", verbose=True)
        mock_setup_id.assert_has_calls(
            [call(self.OPTS, "ord_MSP", "ord0", "orderer", verbose=True)]
        )


class TestGenesisBlock:
    OPTS = {
        "core": {"dir_config": "./config", "dir_crypto": "./crypto"},
        "msps": {"ord_MSP": {"namespace": "ord-ns"}},
        "orderers": {"secret_genesis": "a-genesis-secret", "msp": "ord_MSP"},
    }

    @patch("nephos.fabric.crypto.secret_from_file")
    @patch("nephos.fabric.crypto.print")
    @patch("nephos.fabric.crypto.exists")
    @patch("nephos.fabric.crypto.execute")
    @patch("nephos.fabric.crypto.chdir")
    def test_blocks(
        self, mock_chdir, mock_execute, mock_exists, mock_print, mock_secret_from_file
    ):
        mock_exists.side_effect = [False, False]
        genesis_block(self.OPTS)
        mock_chdir.assert_has_calls([call("./config"), call(PWD)])
        mock_exists.assert_called_once_with("./crypto/genesis.block")
        mock_execute.assert_called_once_with(
            "configtxgen -profile OrdererGenesis -outputBlock ./crypto/genesis.block",
            verbose=False,
        )
        mock_print.assert_not_called()
        mock_secret_from_file.assert_called_once_with(
            secret="a-genesis-secret",
            namespace="ord-ns",
            key="genesis.block",
            filename="./crypto/genesis.block",
            verbose=False,
        )

    @patch("nephos.fabric.crypto.secret_from_file")
    @patch("nephos.fabric.crypto.print")
    @patch("nephos.fabric.crypto.exists")
    @patch("nephos.fabric.crypto.execute")
    @patch("nephos.fabric.crypto.chdir")
    def test_again(
        self, mock_chdir, mock_execute, mock_exists, mock_print, mock_secret_from_file
    ):
        mock_exists.side_effect = [True, True]
        genesis_block(self.OPTS, True)
        mock_chdir.assert_has_calls([call("./config"), call(PWD)])
        mock_exists.assert_called_once_with("./crypto/genesis.block")
        mock_execute.assert_not_called()
        mock_print.assert_called_once_with("./crypto/genesis.block already exists")
        mock_secret_from_file.assert_called_once_with(
            secret="a-genesis-secret",
            namespace="ord-ns",
            key="genesis.block",
            filename="./crypto/genesis.block",
            verbose=True,
        )


class TestChannelTx:
    OPTS = {
        "core": {"dir_config": "./config", "dir_crypto": "./crypto"},
        "msps": {"peer_MSP": {"namespace": "peer-ns"}},
        "peers": {
            "channel_name": "a-channel",
            "channel_profile": "AProfile",
            "msp": "peer_MSP",
            "secret_channel": "a-channel-secret",
        },
    }

    @patch("nephos.fabric.crypto.secret_from_file")
    @patch("nephos.fabric.crypto.print")
    @patch("nephos.fabric.crypto.exists")
    @patch("nephos.fabric.crypto.execute")
    @patch("nephos.fabric.crypto.chdir")
    def test_blocks(
        self, mock_chdir, mock_execute, mock_exists, mock_print, mock_secret_from_file
    ):
        mock_exists.side_effect = [False, False]
        channel_tx(self.OPTS)
        mock_chdir.assert_has_calls([call("./config"), call(PWD)])
        mock_exists.assert_called_once_with("./crypto/a-channel.tx")
        mock_execute.assert_called_once_with(
            "configtxgen -profile AProfile -channelID a-channel -outputCreateChannelTx ./crypto/a-channel.tx",
            verbose=False,
        )
        mock_print.assert_not_called()
        mock_secret_from_file.assert_called_once_with(
            secret="a-channel-secret",
            namespace="peer-ns",
            key="a-channel.tx",
            filename="./crypto/a-channel.tx",
            verbose=False,
        )

    @patch("nephos.fabric.crypto.secret_from_file")
    @patch("nephos.fabric.crypto.print")
    @patch("nephos.fabric.crypto.exists")
    @patch("nephos.fabric.crypto.execute")
    @patch("nephos.fabric.crypto.chdir")
    def test_again(
        self, mock_chdir, mock_execute, mock_exists, mock_print, mock_secret_from_file
    ):
        mock_exists.side_effect = [True, True]
        channel_tx(self.OPTS, True)
        mock_chdir.assert_has_calls([call("./config"), call(PWD)])
        mock_exists.assert_called_once_with("./crypto/a-channel.tx")
        mock_execute.assert_not_called()
        mock_print.assert_called_once_with("./crypto/a-channel.tx already exists")
        mock_secret_from_file.assert_called_once_with(
            secret="a-channel-secret",
            namespace="peer-ns",
            key="a-channel.tx",
            filename="./crypto/a-channel.tx",
            verbose=True,
        )
