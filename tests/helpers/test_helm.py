from collections import namedtuple
from unittest.mock import call, patch

import pytest

from nephos.helpers.helm import (
    helm_init,
    helm_check,
    helm_env_vars,
    helm_preserve,
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
    @patch("nephos.helpers.helm.sleep")
    @patch("nephos.helpers.helm.print")
    @patch("nephos.helpers.helm.execute")
    def test_helm_check(self, mock_execute, mock_print, mock_sleep):
        mock_execute.side_effect = [
            ("Pending", None),  # Get states
            ("a_pod", None),  # Get pods
            ("Running", None),
            ("a_pod", None),
        ]
        helm_check("an_app", "a-release", "a-namespace")
        assert mock_execute.call_count == 4
        mock_print.assert_has_calls(
            [
                call("Ensuring that all pods are running "),
                call(".", end="", flush=True),
                call("All pods in a-release are running"),
            ]
        )
        mock_sleep.assert_called_once()

    @patch("nephos.helpers.helm.sleep")
    @patch("nephos.helpers.helm.print")
    @patch("nephos.helpers.helm.execute")
    def test_helm_check_podnum(self, mock_execute, mock_print, mock_sleep):
        mock_execute.side_effect = [
            ("Pending Running", None),  # Get states
            ("a_pod another_pod", None),  # Get pods
            ("Running Running", None),
            ("a_pod another_pod", None),
        ]
        helm_check("an_app", "a-release", "a-namespace", pod_num=2)
        assert mock_execute.call_count == 4
        mock_print.assert_has_calls(
            [
                call("Ensuring that all pods are running "),
                call(".", end="", flush=True),
                call("All pods in a-release are running"),
            ]
        )
        mock_sleep.assert_called_once()


class TestHelmEnvVars:
    @patch("nephos.helpers.helm.secret_read")
    def test_helm_env_vars_empty(self, mock_secret_read):
        result = helm_env_vars(None)
        assert result == ""
        mock_secret_read.assert_not_called()

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


class TestHelmPreserve:
    @patch("nephos.helpers.helm.secret_read")
    def test_helm_preserve_empty(self, mock_secret_read):
        result = helm_preserve("a-namespace", preserve=None)
        assert result == ""
        mock_secret_read.assert_not_called()

    @patch("nephos.helpers.helm.secret_read")
    def test_helm_preserve(self, mock_secret_read):
        mock_secret_read.side_effect = [{"BAR_ENV": "sausage"}]
        result = helm_preserve(
            "a-namespace", preserve=(("a-secret", "BAR_ENV", "egg"),)
        )
        assert result == " --set egg=sausage"
        mock_secret_read.assert_called_once_with(
            "a-secret", "a-namespace", verbose=False
        )

    @patch("nephos.helpers.helm.secret_read")
    def test_helm_preserve_bad(self, mock_secret_read):
        with pytest.raises(TypeError):
            helm_preserve("a-namespace", preserve=("foo", "egg"))
        mock_secret_read.assert_not_called()

    @patch("nephos.helpers.helm.secret_read")
    def test_helm_preserve_preserve_bad(self, mock_secret_read):
        mock_secret_read.side_effect = [{"BAR_ENV": "sausage"}]
        with pytest.raises(TypeError):
            helm_preserve("a-namespace", preserve=("a-secret", "BAR_ENV"))
        mock_secret_read.assert_not_called()


class TestHelmInstall:
    @patch("nephos.helpers.helm.helm_env_vars")
    @patch("nephos.helpers.helm.helm_check")
    @patch("nephos.helpers.helm.execute")
    def test_helm_install(self, mock_execute, mock_helm_check, mock_helm_env_vars):
        mock_helm_env_vars.side_effect = [""]
        mock_execute.side_effect = [
            (None, "error"),  # Helm list
            ("Helm install", None),  # Helm install
        ]
        helm_install("a_repo", "an_app", "a-release", "a-namespace")
        mock_helm_env_vars.assert_called_once_with(None)
        mock_execute.assert_has_calls(
            [
                call("helm status a-release"),
                call(
                    "helm install a_repo/an_app -n a-release --namespace a-namespace",
                    verbose=False,
                ),
            ]
        )
        mock_helm_check.assert_called_once_with("an_app", "a-release", "a-namespace", 1)

    @patch("nephos.helpers.helm.helm_env_vars")
    @patch("nephos.helpers.helm.helm_check")
    @patch("nephos.helpers.helm.execute")
    def test_helm_install_again(
        self, mock_execute, mock_helm_check, mock_helm_env_vars
    ):
        mock_helm_env_vars.side_effect = [""]
        mock_execute.side_effect = [("a-release", None)]  # Helm list
        helm_install("a_repo", "an_app", "a-release", "a-namespace")
        mock_helm_env_vars.assert_called_once_with(None)
        mock_execute.assert_called_once_with("helm status a-release")
        mock_helm_check.assert_called_once_with("an_app", "a-release", "a-namespace", 1)

    @patch("nephos.helpers.helm.helm_env_vars")
    @patch("nephos.helpers.helm.helm_check")
    @patch("nephos.helpers.helm.execute")
    def test_helm_install_config(
        self, mock_execute, mock_helm_check, mock_helm_env_vars
    ):
        mock_helm_env_vars.side_effect = [""]
        mock_execute.side_effect = [
            (None, "error"),  # Helm list
            ("Helm install", None),  # Helm install
        ]
        helm_install(
            "a_repo",
            "an_app",
            "a-release",
            "a-namespace",
            config_yaml="some_config.yaml",
        )
        mock_helm_env_vars.assert_called_once_with(None)
        mock_execute.assert_has_calls(
            [
                call("helm status a-release"),
                call(
                    "helm install a_repo/an_app -n a-release --namespace a-namespace -f some_config.yaml",
                    verbose=False,
                ),
            ]
        )
        mock_helm_check.assert_called_once_with("an_app", "a-release", "a-namespace", 1)

    @patch("nephos.helpers.helm.helm_env_vars")
    @patch("nephos.helpers.helm.helm_check")
    @patch("nephos.helpers.helm.execute")
    def test_helm_install_envvars(
        self, mock_execute, mock_helm_check, mock_helm_env_vars
    ):
        mock_helm_env_vars.side_effect = [" --set foo=bar"]
        mock_execute.side_effect = [
            (None, "error"),  # Helm list
            ("Helm install", None),  # Helm install
        ]
        helm_install(
            "a_repo",
            "an_app",
            "a-release",
            "a-namespace",
            env_vars="env-vars",
            verbose=True,
        )
        mock_helm_env_vars.assert_called_once_with("env-vars")
        mock_execute.assert_has_calls(
            [
                call("helm status a-release"),
                call(
                    "helm install a_repo/an_app -n a-release --namespace a-namespace "
                    + "--set foo=bar",
                    verbose=True,
                ),
            ]
        )
        mock_helm_check.assert_called_once_with("an_app", "a-release", "a-namespace", 1)


class TestHelmUpgrade:
    @patch("nephos.helpers.helm.helm_preserve")
    @patch("nephos.helpers.helm.helm_env_vars")
    @patch("nephos.helpers.helm.helm_check")
    @patch("nephos.helpers.helm.execute")
    def test_helm_upgrade(
        self, mock_execute, mock_helm_check, mock_helm_env_vars, mock_helm_preserve
    ):
        mock_helm_env_vars.side_effect = [""]
        mock_helm_preserve.side_effect = [""]
        mock_execute.side_effect = [
            ("a-release", None),  # Helm list
            ("Helm install", None),  # Helm install
        ]
        helm_upgrade("a_repo", "an_app", "a-release", "a-namespace")
        mock_helm_env_vars.assert_called_once_with(None)
        mock_helm_preserve.assert_called_once_with("a-namespace", None, verbose=False)
        mock_execute.assert_has_calls(
            [
                call("helm status a-release"),
                call("helm upgrade a-release a_repo/an_app", verbose=False),
            ]
        )
        mock_helm_check.assert_called_once_with("an_app", "a-release", "a-namespace", 1)

    @patch("nephos.helpers.helm.helm_preserve")
    @patch("nephos.helpers.helm.helm_env_vars")
    @patch("nephos.helpers.helm.helm_check")
    @patch("nephos.helpers.helm.execute")
    def test_helm_upgrade_preinstall(
        self, mock_execute, mock_helm_check, mock_helm_env_vars, mock_helm_preserve
    ):
        mock_helm_env_vars.side_effect = [""]
        mock_helm_preserve.side_effect = [""]
        mock_execute.side_effect = [(None, "error")]  # Helm list
        with pytest.raises(Exception):
            helm_upgrade("a_repo", "an_app", "a-release", "a-namespace")
        mock_helm_env_vars.assert_called_once_with(None)
        mock_helm_preserve.assert_called_once_with("a-namespace", None, verbose=False)
        mock_execute.assert_called_once_with("helm status a-release")
        mock_helm_check.assert_not_called()

    @patch("nephos.helpers.helm.helm_preserve")
    @patch("nephos.helpers.helm.helm_env_vars")
    @patch("nephos.helpers.helm.helm_check")
    @patch("nephos.helpers.helm.execute")
    def test_helm_upgrade_config(
        self, mock_execute, mock_helm_check, mock_helm_env_vars, mock_helm_preserve
    ):
        mock_helm_env_vars.side_effect = [""]
        mock_helm_preserve.side_effect = [""]
        mock_execute.side_effect = [
            ("a-release", None),  # Helm list
            ("Helm upgrade", None),  # Helm upgrade
        ]
        helm_upgrade(
            "a_repo",
            "an_app",
            "a-release",
            "a-namespace",
            config_yaml="some_config.yaml",
        )
        mock_helm_env_vars.assert_called_once_with(None)
        mock_helm_preserve.assert_called_once_with("a-namespace", None, verbose=False)
        mock_execute.assert_has_calls(
            [
                call("helm status a-release"),
                call(
                    "helm upgrade a-release a_repo/an_app -f some_config.yaml",
                    verbose=False,
                ),
            ]
        )
        mock_helm_check.assert_called_once_with("an_app", "a-release", "a-namespace", 1)

    @patch("nephos.helpers.helm.helm_preserve")
    @patch("nephos.helpers.helm.helm_env_vars")
    @patch("nephos.helpers.helm.helm_check")
    @patch("nephos.helpers.helm.execute")
    def test_helm_upgrade_preserve(
        self, mock_execute, mock_helm_check, mock_helm_env_vars, mock_helm_preserve
    ):
        mock_helm_env_vars.side_effect = [" --set foo=bar"]
        mock_helm_preserve.side_effect = [" --set egg=sausage"]
        mock_execute.side_effect = [
            ("a-release", None),  # Helm list
            ("Helm upgrade", None),  # Helm upgrade
        ]
        helm_upgrade(
            "a_repo",
            "an_app",
            "a-release",
            "a-namespace",
            env_vars="env-vars",
            preserve="preserve",
            verbose=True,
        )
        mock_helm_env_vars.assert_called_once_with("env-vars")
        mock_helm_preserve.assert_called_once_with(
            "a-namespace", "preserve", verbose=True
        )
        mock_execute.assert_has_calls(
            [
                call("helm status a-release"),
                call(
                    "helm upgrade a-release a_repo/an_app --set foo=bar --set egg=sausage",
                    verbose=True,
                ),
            ]
        )
        mock_helm_check.assert_called_once_with("an_app", "a-release", "a-namespace", 1)
