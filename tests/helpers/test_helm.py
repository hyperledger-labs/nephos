from collections import namedtuple
from unittest.mock import call, patch

import pytest

from nephos.helpers.helm import (
    helm_init,
    helm_check,
    helm_env_vars,
    helm_preserve,
    helm_extra_vars,
    helm_install,
    helm_upgrade,
)

# NamedTuples for mocking
ConfigMap = namedtuple("ConfigMap", ("data",))
Secret = namedtuple("Secret", ("data",))
IngressHost = namedtuple("IngressHost", ("host",))


class TestHelmInit:
    @patch("nephos.helpers.helm.sleep")
    @patch("nephos.helpers.helm.print")
    @patch("nephos.helpers.helm.execute")
    def test_helm_init(self, mock_execute, mock_print, mock_sleep):
        mock_execute.side_effect = [
            (None, "error"),
            ("RBAC created", None),
            ("Helm init", None),
            ("false", None),  # automountServiceAccountToken
            ("automountServiceAccountToken updated", None),
            (None, "error"),  # Helm not operational yet
            ("Helm list", None),
        ]
        helm_init()
        assert mock_execute.call_count == 7
        mock_print.assert_called_once_with(".", end="", flush=True)
        mock_sleep.assert_called_once()

    @patch("nephos.helpers.helm.sleep")
    @patch("nephos.helpers.helm.print")
    @patch("nephos.helpers.helm.execute")
    def test_helm_init_repeat(self, mock_execute, mock_print, mock_sleep):
        mock_execute.side_effect = [("Helm list", None)]
        helm_init()
        mock_execute.assert_called_once()
        mock_print.assert_called_once_with("Helm is already installed!")
        mock_sleep.assert_not_called()


class TestHelmCheck:
    @patch("nephos.helpers.helm.pod_check")
    def test_helm_check(self, mock_pod_check):
        helm_check("an_app", "a-release", "a-namespace")
        mock_pod_check.assert_called_once_with(
            "a-namespace", '-l "app=an_app,release=a-release"', pod_num=None
        )

    @patch("nephos.helpers.helm.pod_check")
    def test_helm_check_podnum(self, mock_pod_check):
        helm_check("an_app", "a-release", "a-namespace", pod_num=2)
        mock_pod_check.assert_called_once_with(
            "a-namespace", '-l "app=an_app,release=a-release"', pod_num=2
        )


class TestHelmEnvVars:
    @patch("nephos.helpers.helm.secret_read")
    def test_helm_env_vars_values(self, mock_secret_read):
        result = helm_env_vars((("foo", "bar"), ("egg", "sausage", True)))
        assert result == " --set foo=bar --set-string egg=sausage"
        mock_secret_read.assert_not_called()

    @patch("nephos.helpers.helm.secret_read")
    def test_helm_env_vars_bad(self, mock_secret_read):
        with pytest.raises(TypeError):
            helm_env_vars(("foo", "egg"))
        mock_secret_read.assert_not_called()

    @patch("nephos.helpers.helm.secret_read")
    def test_helm_env_vars_emptyerror(self, mock_secret_read):
        with pytest.raises(TypeError):
            helm_env_vars()
        mock_secret_read.assert_not_called()


class TestHelmPreserve:
    @patch("nephos.helpers.helm.secret_read")
    def test_helm_preserve_empty(self, mock_secret_read):
        with pytest.raises(TypeError):
            helm_preserve()
        mock_secret_read.assert_not_called()

    @patch("nephos.helpers.helm.secret_read")
    def test_helm_preserve(self, mock_secret_read):
        mock_secret_read.side_effect = [{"BAR_ENV": "sausage"}]
        result = helm_preserve(
            preserve=(("a-namespace", "a-secret", "BAR_ENV", "egg"),)
        )
        assert result == " --set egg=sausage"
        mock_secret_read.assert_called_once_with(
            "a-secret", "a-namespace", verbose=False
        )

    @patch("nephos.helpers.helm.secret_read")
    def test_helm_preserve_bad(self, mock_secret_read):
        with pytest.raises(TypeError):
            helm_preserve(preserve=("foo", "egg"))
        mock_secret_read.assert_not_called()


class TestHelmExtraVars:
    @patch("nephos.helpers.helm.helm_preserve")
    @patch("nephos.helpers.helm.helm_env_vars")
    def test_helm_extra_vars(self, mock_helm_env_vars, mock_helm_preserve):
        result = helm_extra_vars()
        mock_helm_env_vars.assert_not_called()
        mock_helm_preserve.assert_not_called()
        assert result == ""

    @patch("nephos.helpers.helm.helm_preserve")
    @patch("nephos.helpers.helm.helm_env_vars")
    def test_helm_extra_vars_everything(self, mock_helm_env_vars, mock_helm_preserve):
        mock_helm_env_vars.side_effect = [" --set foo=bar"]
        mock_helm_preserve.side_effect = [" --set egg=sausage"]
        result = helm_extra_vars(
            version="a-version",
            config_yaml="some-config",
            env_vars="some-env-vars",
            preserve="some-preserve",
            verbose=True,
        )
        mock_helm_env_vars.assert_called_once_with("some-env-vars")
        mock_helm_preserve.assert_called_once_with("some-preserve", verbose=True)
        assert (
            result
            == " --version a-version -f some-config --set foo=bar --set egg=sausage"
        )

    @patch("nephos.helpers.helm.helm_preserve")
    @patch("nephos.helpers.helm.helm_env_vars")
    def test_helm_extra_vars_multiconf(self, mock_helm_env_vars, mock_helm_preserve):
        result = helm_extra_vars(config_yaml=("some-config", "another-config"))
        mock_helm_env_vars.assert_not_called()
        mock_helm_preserve.assert_not_called()
        assert result == " -f some-config -f another-config"

    @patch("nephos.helpers.helm.helm_preserve")
    @patch("nephos.helpers.helm.helm_env_vars")
    def test_helm_extra_vars_errorconf(self, mock_helm_env_vars, mock_helm_preserve):
        with pytest.raises(ValueError):
            helm_extra_vars(config_yaml={"some-config": "another-config"})
        mock_helm_env_vars.assert_not_called()
        mock_helm_preserve.assert_not_called()


class TestHelmInstall:
    @patch("nephos.helpers.helm.execute")
    def test_helm_install(self, mock_execute):
        mock_execute.side_effect = [
            (None, "error"),  # Helm list
            ("Helm install", None),  # Helm install
        ]
        helm_install("a_repo", "an_app", "a-release", "a-namespace")
        mock_execute.assert_has_calls(
            [
                call("helm status a-release"),
                call(
                    "helm install a_repo/an_app -n a-release --namespace a-namespace",
                    verbose=False,
                ),
            ]
        )

    @patch("nephos.helpers.helm.execute")
    def test_helm_install_again(self, mock_execute):
        mock_execute.side_effect = [("a-release", None)]  # Helm list
        helm_install("a_repo", "an_app", "a-release", "a-namespace")
        mock_execute.assert_called_once_with("helm status a-release")

    @patch("nephos.helpers.helm.execute")
    def test_helm_install_extra(self, mock_execute):
        mock_execute.side_effect = [
            (None, "error"),  # Helm list
            ("Helm install", None),  # Helm install
        ]
        helm_install(
            "a_repo", "an_app", "a-release", "a-namespace", extra_vars=" EXTRA-VARS"
        )
        mock_execute.assert_has_calls(
            [
                call("helm status a-release"),
                call(
                    "helm install a_repo/an_app -n a-release "
                    + "--namespace a-namespace EXTRA-VARS",
                    verbose=False,
                ),
            ]
        )


class TestHelmUpgrade:
    @patch("nephos.helpers.helm.execute")
    def test_helm_upgrade(self, mock_execute):
        mock_execute.side_effect = [
            ("a-release", None),  # Helm list
            ("Helm install", None),  # Helm install
        ]
        helm_upgrade("a_repo", "an_app", "a-release")
        mock_execute.assert_has_calls(
            [
                call("helm status a-release"),
                call("helm upgrade a-release a_repo/an_app", verbose=False),
            ]
        )

    @patch("nephos.helpers.helm.execute")
    def test_helm_upgrade_preinstall(self, mock_execute):
        mock_execute.side_effect = [(None, "error")]  # Helm list
        with pytest.raises(Exception):
            helm_upgrade("a_repo", "an_app", "a-release")
        mock_execute.assert_called_once_with("helm status a-release")

    @patch("nephos.helpers.helm.execute")
    def test_helm_upgrade_extra_vars(self, mock_execute):
        mock_execute.side_effect = [
            ("a-release", None),  # Helm list
            ("Helm upgrade", None),  # Helm upgrade
        ]
        helm_upgrade("a_repo", "an_app", "a-release", extra_vars=" EXTRA-VARS")
        mock_execute.assert_has_calls(
            [
                call("helm status a-release"),
                call("helm upgrade a-release a_repo/an_app EXTRA-VARS", verbose=False),
            ]
        )
