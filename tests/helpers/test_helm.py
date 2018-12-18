from collections import namedtuple
from unittest import mock
from unittest.mock import call

import pytest

from helpers.helm import helm_init, helm_check, helm_install, helm_upgrade

# NamedTuples for mocking
ConfigMap = namedtuple('ConfigMap', ('data',))
Secret = namedtuple('Secret', ('data',))
IngressHost = namedtuple('IngressHost', ('host',))


class TestHelmInit:
    @mock.patch('helpers.helm.sleep')
    @mock.patch('helpers.helm.print')
    @mock.patch('helpers.helm.execute')
    def test_helm_init(self, mock_execute, mock_print, mock_sleep):
        mock_execute.side_effect = [
            None,
            'RBAC created',
            'Helm init',
            'false',  # automountServiceAccountToken
            'automountServiceAccountToken updated',
            None,  # Helm not operational yet
            'Helm list'
        ]
        helm_init()
        assert mock_execute.call_count == 7
        mock_print.assert_called_once_with('.', end='', flush=True)
        mock_sleep.assert_called_once()

    @mock.patch('helpers.helm.sleep')
    @mock.patch('helpers.helm.print')
    @mock.patch('helpers.helm.execute')
    def test_helm_init_repeat(self, mock_execute, mock_print, mock_sleep):
        mock_execute.side_effect = [
            'Helm list'
        ]
        helm_init()
        mock_execute.assert_called_once()
        mock_print.assert_called_once_with('Helm is already installed!')
        mock_sleep.assert_not_called()


class TestHelmCheck:
    @mock.patch('helpers.helm.sleep')
    @mock.patch('helpers.helm.print')
    @mock.patch('helpers.helm.execute')
    def test_helm_check(self, mock_execute, mock_print, mock_sleep):
        mock_execute.side_effect = [
            'Pending',  # Get states
            'a_pod',  # Get pods
            'Running',
            'a_pod'
        ]
        helm_check('an_app', 'a-release', 'a-namespace')
        assert mock_execute.call_count == 4
        mock_print.assert_has_calls([call('Ensuring that all pods are running '),
                                     call('.', end='', flush=True),
                                     call('All pods in a-release are running')])
        mock_sleep.assert_called_once()

    @mock.patch('helpers.helm.sleep')
    @mock.patch('helpers.helm.print')
    @mock.patch('helpers.helm.execute')
    def test_helm_check_podnum(self, mock_execute, mock_print, mock_sleep):
        mock_execute.side_effect = [
            'Pending Running',  # Get states
            'a_pod another_pod',  # Get pods
            'Running Running',
            'a_pod another_pod'
        ]
        helm_check('an_app', 'a-release', 'a-namespace', pod_num=2)
        assert mock_execute.call_count == 4
        mock_print.assert_has_calls([call('Ensuring that all pods are running '),
                                     call('.', end='', flush=True),
                                     call('All pods in a-release are running')])
        mock_sleep.assert_called_once()


class TestHelmInstall:
    @mock.patch('helpers.helm.helm_check')
    @mock.patch('helpers.helm.execute')
    def test_helm_install(self, mock_execute, mock_helm_check):
        mock_execute.side_effect = [
            None,  # Helm list
            None,  # Helm install
        ]
        helm_install('a_repo', 'an_app', 'a-release', 'a-namespace')
        mock_execute.assert_has_calls([
            call('helm status a-release'),
            call('helm install a_repo/an_app -n a-release --namespace a-namespace', verbose=False)
        ])
        mock_helm_check.assert_called_once_with('an_app', 'a-release', 'a-namespace', 1)

    @mock.patch('helpers.helm.helm_check')
    @mock.patch('helpers.helm.execute')
    def test_helm_install_again(self, mock_execute, mock_helm_check):
        mock_execute.side_effect = [
            'a-release',  # Helm list
        ]
        helm_install('a_repo', 'an_app', 'a-release', 'a-namespace')
        mock_execute.assert_called_once_with('helm status a-release')
        mock_helm_check.assert_called_once_with('an_app', 'a-release', 'a-namespace', 1)

    @mock.patch('helpers.helm.helm_check')
    @mock.patch('helpers.helm.execute')
    def test_helm_install_config(self, mock_execute, mock_helm_check):
        mock_execute.side_effect = [
            None,  # Helm list
            None,  # Helm install
        ]
        helm_install('a_repo', 'an_app', 'a-release', 'a-namespace', config_yaml='some_config.yaml')
        mock_execute.assert_has_calls([
            call('helm status a-release'),
            call('helm install a_repo/an_app -n a-release --namespace a-namespace -f some_config.yaml', verbose=False)
        ])
        mock_helm_check.assert_called_once_with('an_app', 'a-release', 'a-namespace', 1)

    @mock.patch('helpers.helm.helm_check')
    @mock.patch('helpers.helm.execute')
    def test_helm_install_envvars(self, mock_execute, mock_helm_check):
        mock_execute.side_effect = [
            None,  # Helm list
            None,  # Helm install
        ]
        helm_install('a_repo', 'an_app', 'a-release', 'a-namespace', env_vars=(
            ('foo', 'bar'), ('egg', 'sausage', True)
        ))
        mock_execute.assert_has_calls([
            call('helm status a-release'),
            call('helm install a_repo/an_app -n a-release --namespace a-namespace ' +
                 '--set foo=bar --set-string egg=sausage', verbose=False)
        ])
        mock_helm_check.assert_called_once_with('an_app', 'a-release', 'a-namespace', 1)

    @mock.patch('helpers.helm.helm_check')
    @mock.patch('helpers.helm.execute')
    def test_helm_install_verbose(self, mock_execute, mock_helm_check):
        mock_execute.side_effect = [
            None,  # Helm list
            None,  # Helm install
        ]
        helm_install('a_repo', 'an_app', 'a-release', 'a-namespace', verbose=True)
        mock_execute.assert_has_calls([
            call('helm status a-release'),
            call('helm install a_repo/an_app -n a-release --namespace a-namespace', verbose=True)
        ])
        mock_helm_check.assert_called_once_with('an_app', 'a-release', 'a-namespace', 1)



class TestHelmUpgrade:
    @mock.patch('helpers.helm.helm_check')
    @mock.patch('helpers.helm.execute')
    def test_helm_upgrade(self, mock_execute, mock_helm_check):
        mock_execute.side_effect = [
            'a-release',  # Helm list
            None,  # Helm install
        ]
        helm_upgrade('a_repo', 'an_app', 'a-release', 'a-namespace')
        mock_execute.assert_has_calls([
            call('helm status a-release'),
            call('helm upgrade a-release a_repo/an_app', verbose=False)
        ])
        mock_helm_check.assert_called_once_with('an_app', 'a-release', 'a-namespace', 1)

    @mock.patch('helpers.helm.helm_check')
    @mock.patch('helpers.helm.execute')
    def test_helm_upgrade_preinstall(self, mock_execute, mock_helm_check):
        mock_execute.side_effect = [
            None,  # Helm list
        ]
        with pytest.raises(Exception):
            helm_upgrade('a_repo', 'an_app', 'a-release', 'a-namespace')
        mock_execute.assert_called_once_with('helm status a-release')
        mock_helm_check.assert_not_called()

    @mock.patch('helpers.helm.helm_check')
    @mock.patch('helpers.helm.execute')
    def test_helm_upgrade_config(self, mock_execute, mock_helm_check):
        mock_execute.side_effect = [
            'a-release',  # Helm list
            None,  # Helm install
        ]
        helm_upgrade('a_repo', 'an_app', 'a-release', 'a-namespace', config_yaml='some_config.yaml')
        mock_execute.assert_has_calls([
            call('helm status a-release'),
            call('helm upgrade a-release a_repo/an_app -f some_config.yaml', verbose=False)
        ])
        mock_helm_check.assert_called_once_with('an_app', 'a-release', 'a-namespace', 1)

    @mock.patch('helpers.helm.helm_check')
    @mock.patch('helpers.helm.execute')
    def test_helm_upgrade_envvars(self, mock_execute, mock_helm_check):
        mock_execute.side_effect = [
            'a-release',  # Helm list
            None,  # Helm install
        ]
        helm_upgrade('a_repo', 'an_app', 'a-release', 'a-namespace', env_vars=(
            ('foo', 'bar'), ('egg', 'sausage', True)
        ))
        mock_execute.assert_has_calls([
            call('helm status a-release'),
            call('helm upgrade a-release a_repo/an_app ' +
                 '--set foo=bar --set-string egg=sausage', verbose=False)
        ])
        mock_helm_check.assert_called_once_with('an_app', 'a-release', 'a-namespace', 1)

    @mock.patch('helpers.helm.secret_read')
    @mock.patch('helpers.helm.helm_check')
    @mock.patch('helpers.helm.execute')
    def test_helm_upgrade_preserve(self, mock_execute, mock_helm_check, mock_secret_read):
        mock_execute.side_effect = [
            'a-release',  # Helm list
            None,  # Helm install
        ]
        mock_secret_read.side_effect = [{'BAR_ENV': 'bar'}]
        helm_upgrade('a_repo', 'an_app', 'a-release', 'a-namespace', preserve=(
            ('a_secret', 'BAR_ENV', 'foo'),
        ))
        mock_execute.assert_has_calls([
            call('helm status a-release'),
            call('helm upgrade a-release a_repo/an_app ' +
                 '--set foo=bar', verbose=False)
        ])
        mock_helm_check.assert_called_once_with('an_app', 'a-release', 'a-namespace', 1)

    @mock.patch('helpers.helm.helm_check')
    @mock.patch('helpers.helm.execute')
    def test_helm_upgrade_verbose(self, mock_execute, mock_helm_check):
        mock_execute.side_effect = [
            'a-release',  # Helm list
            None,  # Helm install
        ]
        helm_upgrade('a_repo', 'an_app', 'a-release', 'a-namespace', verbose=True)
        mock_execute.assert_has_calls([
            call('helm status a-release'),
            call('helm upgrade a-release a_repo/an_app', verbose=True)
        ])
        mock_helm_check.assert_called_once_with('an_app', 'a-release', 'a-namespace', 1)
