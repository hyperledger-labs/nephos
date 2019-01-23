from collections import namedtuple
from unittest import mock

from kubernetes.client.rest import ApiException
import pytest

from nephos.helpers.k8s import (Executer,
                                context_get, ns_create, ns_read, ingress_read, cm_create, cm_read,
                                get_app_info,
                                secret_create, secret_read, secret_from_file)

# NamedTuples for mocking
ConfigMap = namedtuple('ConfigMap', ('data',))
Secret = namedtuple('Secret', ('data',))
IngressHost = namedtuple('IngressHost', ('host',))


class TestExecuter:
    def test_executer_init(self):
        executer = Executer('a-pod', 'a-namespace')
        assert executer.pod == 'a-pod'
        assert executer.prefix_exec == "kubectl exec a-pod -n a-namespace -- "
        assert executer.verbose is False

    def test_executer_init_container(self):
        executer = Executer('a-pod', 'a-namespace', container='a_container')
        assert executer.pod == 'a-pod'
        assert executer.prefix_exec == "kubectl exec a-pod -n a-namespace --container a_container -- "
        assert executer.verbose is False

    def test_executer_init_verbose(self):
        executer = Executer('a-pod', 'a-namespace', verbose=True)
        assert executer.pod == 'a-pod'
        assert executer.prefix_exec == "kubectl exec a-pod -n a-namespace -- "
        assert executer.verbose is True

    @mock.patch('nephos.helpers.k8s.execute')
    def test_executer_execute(self, mock_execute):
        mock_execute.side_effect = [('result', None)]
        executer = Executer('a_pod', 'a-namespace')
        executer.execute('a_command')
        mock_execute.assert_called_once_with(
            'kubectl exec a_pod -n a-namespace -- a_command', verbose=False)

    @mock.patch('nephos.helpers.k8s.execute')
    def test_executer_execute_verbose(self, mock_execute):
        mock_execute.side_effect = [('result', None)]
        executer = Executer('a_pod', 'a-namespace', verbose=True)
        executer.execute('a_command')
        mock_execute.assert_called_once_with(
            'kubectl exec a_pod -n a-namespace -- a_command', verbose=True)

    @mock.patch('nephos.helpers.k8s.execute')
    def test_executer_logs(self, mock_execute):
        mock_execute.side_effect = [('result', None)]
        executer = Executer('a_pod', 'a-namespace')
        executer.logs()
        mock_execute.assert_called_once_with(
            'kubectl logs a_pod -n a-namespace --tail=-1', verbose=False)

    @mock.patch('nephos.helpers.k8s.execute')
    def test_executer_logs_tail(self, mock_execute):
        mock_execute.side_effect = [('result', None)]
        executer = Executer('a_pod', 'a-namespace', container='a_container', verbose=True)
        executer.logs(10)
        mock_execute.assert_called_once_with(
            'kubectl logs a_pod -n a-namespace --container a_container --tail=10', verbose=True)


class TestContextGet:
    CONTEXTS = ({'all': 'contexts'}, {'active': 'context'})

    @mock.patch('nephos.helpers.k8s.pretty_print')
    @mock.patch('nephos.helpers.k8s.config')
    def test_context_get(self, mock_config, mock_pretty_print):
        mock_config.list_kube_config_contexts.side_effect = [self.CONTEXTS]
        context = context_get()
        mock_config.list_kube_config_contexts.assert_called_once_with()
        mock_pretty_print.assert_not_called()
        assert context == self.CONTEXTS[1]

    @mock.patch('nephos.helpers.k8s.pretty_print')
    @mock.patch('nephos.helpers.k8s.config')
    def test_context_get_verbose(self, mock_config, mock_pretty_print):
        mock_config.list_kube_config_contexts.side_effect = [self.CONTEXTS]
        context = context_get(verbose=True)
        mock_config.list_kube_config_contexts.assert_called_once_with()
        mock_pretty_print.assert_called_once()
        assert context == self.CONTEXTS[1]


class TestNsCreate:
    @mock.patch('nephos.helpers.k8s.print')
    @mock.patch('nephos.helpers.k8s.api')
    @mock.patch('nephos.helpers.k8s.ns_read')
    def test_ns_create_new(self, mock_ns_read, mock_api, mock_print):
        # TODO: We should ideally replicate the correct API exception
        mock_ns_read.side_effect = ApiException()
        ns_create('a-namespace')
        mock_ns_read.assert_called_once_with('a-namespace', verbose=False)
        mock_api.create_namespace.assert_called_once()
        mock_print.assert_not_called()

    @mock.patch('nephos.helpers.k8s.print')
    @mock.patch('nephos.helpers.k8s.api')
    @mock.patch('nephos.helpers.k8s.ns_read')
    def test_ns_create_new_verbose(self, mock_ns_read, mock_api, mock_print):
        # TODO: We should ideally replicate the correct API exception
        mock_ns_read.side_effect = ApiException()
        ns_create('a-namespace', verbose=True)
        mock_ns_read.assert_called_once_with('a-namespace', verbose=True)
        mock_api.create_namespace.assert_called_once()
        mock_print.assert_called_once_with('Created namespace "a-namespace"')

    @mock.patch('nephos.helpers.k8s.print')
    @mock.patch('nephos.helpers.k8s.api')
    @mock.patch('nephos.helpers.k8s.ns_read')
    def test_ns_create_old(self, mock_ns_read, mock_api, mock_print):
        ns_create('a-namespace')
        mock_ns_read.assert_called_once_with('a-namespace', verbose=False)
        mock_api.create_namespace.assert_not_called()
        mock_print.assert_not_called()


class TestNsRead:
    @mock.patch('nephos.helpers.k8s.pretty_print')
    @mock.patch('nephos.helpers.k8s.api')
    def test_ns_read(self, mock_api, mock_pretty_print):
        ns_read('a-namespace')
        mock_api.read_namespace.assert_called_with(name='a-namespace')
        mock_pretty_print.assert_not_called()

    @mock.patch('nephos.helpers.k8s.pretty_print')
    @mock.patch('nephos.helpers.k8s.api')
    def test_ns_read_verbose(self, mock_api, mock_pretty_print):
        ns_read('a-namespace', verbose=True)
        mock_api.read_namespace.assert_called_with(name='a-namespace')
        mock_pretty_print.assert_called_once()


class TestIngressRead:
    @mock.patch('nephos.helpers.k8s.pretty_print')
    @mock.patch('nephos.helpers.k8s.api_ext')
    def test_ingress_read(self, mock_api_ext, mock_pretty_print):
        mock_ingress = mock.MagicMock()
        mock_ingress.spec.rules.__getitem__.side_effect = [IngressHost('a-url'), IngressHost('another-url')]
        mock_api_ext.read_namespaced_ingress.side_effect = [mock_ingress]
        ingress_read('an_ingress', 'a-namespace')
        mock_api_ext.read_namespaced_ingress.assert_called_once_with(
            name='an_ingress', namespace='a-namespace')
        mock_pretty_print.assert_not_called()

    @mock.patch('nephos.helpers.k8s.pretty_print')
    @mock.patch('nephos.helpers.k8s.api_ext')
    def test_ingress_read_verbose(self, mock_api_ext, mock_pretty_print):
        mock_ingress = mock.MagicMock()
        mock_ingress.spec.rules.__iter__.return_value = [IngressHost('a-url'), IngressHost('another-url')]
        mock_api_ext.read_namespaced_ingress.side_effect = [mock_ingress]
        ingress_read('an_ingress', 'a-namespace', verbose=True)
        mock_api_ext.read_namespaced_ingress.assert_called_once_with(
            name='an_ingress', namespace='a-namespace')
        mock_pretty_print.assert_called_once_with('["a-url", "another-url"]')

    @mock.patch('nephos.helpers.k8s.pretty_print')
    @mock.patch('nephos.helpers.k8s.api_ext')
    def test_ingress_read_fail(self, mock_api_ext, mock_pretty_print):
        mock_api_ext.read_namespaced_ingress.side_effect = [ApiException]
        with pytest.raises(ApiException):
            ingress_read('an_ingress', 'a-namespace', verbose=True)
        mock_api_ext.read_namespaced_ingress.assert_called_once_with(
            name='an_ingress', namespace='a-namespace')
        mock_pretty_print.assert_not_called()


class TestCmCreate:
    @mock.patch('nephos.helpers.k8s.api')
    def test_cm_create(self, mock_api):
        cm_create('a-namespace', 'a_configmap', {'a_key': 'a_value'})
        mock_api.create_namespaced_config_map.assert_called_once()


class TestCmRead:
    @mock.patch('nephos.helpers.k8s.pretty_print')
    @mock.patch('nephos.helpers.k8s.api')
    def test_cm_read(self, mock_api, mock_pretty_print):
        cm_read('a_configmap', 'a-namespace')
        mock_api.read_namespaced_config_map.assert_called_once_with(
            name='a_configmap', namespace='a-namespace')
        mock_pretty_print.assert_not_called()

    @mock.patch('nephos.helpers.k8s.pretty_print')
    @mock.patch('nephos.helpers.k8s.api')
    def test_cm_read_verbose(self, mock_api, mock_pretty_print):
        mock_api.read_namespaced_config_map.side_effect = [ConfigMap({'a_key': 'a_value'})]
        cm_read('a_configmap', 'a-namespace', verbose=True)
        mock_api.read_namespaced_config_map.assert_called_once_with(
            name='a_configmap', namespace='a-namespace')
        mock_pretty_print.assert_called_once_with('{"a_key": "a_value"}')


class TestSecretCreate:
    @mock.patch('nephos.helpers.k8s.print')
    @mock.patch('nephos.helpers.k8s.api')
    def test_secret_create(selfself, mock_api, mock_print):
        secret_create({'a_key': 'a_value'}, 'a_secret', 'a-namespace')
        mock_api.create_namespaced_secret.assert_called_once()
        mock_print.assert_not_called()

    @mock.patch('nephos.helpers.k8s.print')
    @mock.patch('nephos.helpers.k8s.api')
    def test_secret_create_verbose(self, mock_api, mock_print):
        secret_create({'a_key': 'a_value'}, 'a_secret', 'a-namespace', verbose=True)
        mock_api.create_namespaced_secret.assert_called_once()
        mock_print.assert_called_once_with('Created secret a_secret in namespace a-namespace')


class TestSecretRead:
    @mock.patch('nephos.helpers.k8s.pretty_print')
    @mock.patch('nephos.helpers.k8s.api')
    def test_secret_read(self, mock_api, mock_pretty_print):
        mock_api.read_namespaced_secret.side_effect = [Secret({'a_key': b'YV92YWx1ZQ=='})]
        secret_read('a_secret', 'a-namespace')
        mock_api.read_namespaced_secret.assert_called_once_with(
            name='a_secret', namespace='a-namespace')
        mock_pretty_print.assert_not_called()

    @mock.patch('nephos.helpers.k8s.pretty_print')
    @mock.patch('nephos.helpers.k8s.api')
    def test_secret_read_verbose(self, mock_api, mock_pretty_print):
        mock_api.read_namespaced_secret.side_effect = [Secret({'a_key': b'YV92YWx1ZQ=='})]
        secret_read('a_secret', 'a-namespace', verbose=True)
        mock_api.read_namespaced_secret.assert_called_once_with(
            name='a_secret', namespace='a-namespace')
        mock_pretty_print.assert_called_once_with('{"a_key": "a_value"}')

    @mock.patch('nephos.helpers.k8s.pretty_print')
    @mock.patch('nephos.helpers.k8s.api')
    def test_secret_read_unicode(self, mock_api, mock_pretty_print):
        mock_api.read_namespaced_secret.side_effect = [Secret({'a_key': b'YV92YWx1ZYE='})]
        secret_read('a_secret', 'a-namespace', verbose=True)
        mock_api.read_namespaced_secret.assert_called_once_with(
            name='a_secret', namespace='a-namespace')
        mock_pretty_print.assert_called_once_with('{"a_key": "a_value"}')


class TestSecretFromFile:
    @mock.patch('nephos.helpers.k8s.open')
    @mock.patch('nephos.helpers.k8s.input_files')
    @mock.patch('nephos.helpers.k8s.secret_create')
    @mock.patch('nephos.helpers.k8s.secret_read')
    def test_secret_from_file(self, mock_secret_read, mock_secret_create, mock_input_files, mock_open):
        mock_secret_read.side_effect = ApiException()
        secret_from_file('a_secret', 'a-namespace')
        mock_secret_read.assert_called_once()
        mock_secret_create.assert_called_once()
        mock_input_files.assert_called_once()
        mock_open.assert_not_called()

    @mock.patch('nephos.helpers.k8s.open')
    @mock.patch('nephos.helpers.k8s.input_files')
    @mock.patch('nephos.helpers.k8s.secret_create')
    @mock.patch('nephos.helpers.k8s.secret_read')
    def test_secret_from_file_define(self, mock_secret_read, mock_secret_create, mock_input_files, mock_open):
        mock_secret_read.side_effect = ApiException()
        secret_from_file('a_secret', 'a-namespace', filename='./some_file.txt')
        mock_secret_read.assert_called_once()
        mock_secret_create.assert_called_once()
        mock_input_files.assert_not_called()
        mock_open.assert_called_once()


class TestGetAppInfo:
    @mock.patch('nephos.helpers.k8s.secret_read')
    @mock.patch('nephos.helpers.k8s.ingress_read')
    def test_get_app_info(self, mock_ingress_read, mock_secret_read):
        mock_secret_read.side_effect = [{'API_KEY': 'an-api-key'}]
        mock_ingress_read.side_effect = [['a-url']]
        get_app_info('a-namespace', 'an-ingress', 'a-secret')
        mock_ingress_read.assert_called_once_with('an-ingress', namespace='a-namespace', verbose=False)

    @mock.patch('nephos.helpers.k8s.secret_read')
    @mock.patch('nephos.helpers.k8s.ingress_read')
    def test_get_app_info_missingsecret(self, mock_ingress_read, mock_secret_read):
        mock_secret_read.side_effect = [ApiException]
        with pytest.raises(ApiException):
            get_app_info('a-namespace', 'an-ingress', 'a-secret', verbose=True)
        mock_ingress_read.assert_called_once_with('an-ingress', namespace='a-namespace', verbose=True)
        mock_secret_read.assert_called_once_with('a-secret', 'a-namespace', verbose=True)

    @mock.patch('nephos.helpers.k8s.secret_read')
    @mock.patch('nephos.helpers.k8s.ingress_read')
    def test_get_app_info_noingress(self, mock_ingress_read, mock_secret_read):
        mock_secret_read.side_effect = [{'CUSTOM_KEY': 'an-api-key'}]
        mock_ingress_read.side_effect = [ApiException]
        with pytest.raises(ApiException):
            get_app_info('a-namespace', 'an-ingress', 'a-secret', secret_key='CUSTOM_KEY', verbose=True)
        mock_ingress_read.assert_called_once_with('an-ingress', namespace='a-namespace', verbose=True)
        mock_secret_read.assert_not_called()
