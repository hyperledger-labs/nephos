from string import ascii_letters, digits, punctuation
from unittest import mock

from kubernetes.client.rest import ApiException
import pytest

from nephos.fabric.utils import rand_string, credentials_secret, crypto_secret, get_pod


class TestRandString:
    def test_rand_string(self):
        a_string = rand_string(16)
        assert len(a_string) == 16
        assert set(ascii_letters + digits).intersection(set(a_string))
        assert not set(punctuation).intersection(set(a_string))

    def test_rand_string_(self):
        a_string = rand_string(24)
        assert len(a_string) == 24


class TestCredentialsSecret:
    SECRET_DATA = {'CA_USERNAME': 'a-user', 'CA_PASSWORD': 'a-password'}

    @mock.patch('nephos.fabric.utils.secret_read')
    @mock.patch('nephos.fabric.utils.secret_create')
    @mock.patch('nephos.fabric.utils.rand_string')
    def test_credentials_secret(self, mock_rand_string, mock_secret_create, mock_secret_read):
        mock_secret_read.side_effect = [ApiException]
        mock_rand_string.side_effect = ['a-password']
        credentials_secret('a-secret', 'a-namespace', 'a-user')
        mock_secret_read.assert_called_once_with('a-secret', 'a-namespace', verbose=False)
        mock_rand_string.assert_called_once_with(24)
        mock_secret_create.assert_called_once_with(self.SECRET_DATA, 'a-secret', 'a-namespace')

    @mock.patch('nephos.fabric.utils.secret_read')
    @mock.patch('nephos.fabric.utils.secret_create')
    @mock.patch('nephos.fabric.utils.rand_string')
    def test_credentials_secret_again(self, mock_rand_string, mock_secret_create, mock_secret_read):
        mock_secret_read.side_effect = [self.SECRET_DATA]
        credentials_secret('a-secret', 'a-namespace', 'a-user', 'a-password')
        mock_secret_read.assert_called_once_with('a-secret', 'a-namespace', verbose=False)
        mock_rand_string.assert_not_called()
        mock_secret_create.assert_not_called()

    @mock.patch('nephos.fabric.utils.secret_read')
    @mock.patch('nephos.fabric.utils.secret_create')
    @mock.patch('nephos.fabric.utils.rand_string')
    def test_credentials_secret_badpassword(self, mock_rand_string, mock_secret_create, mock_secret_read):
        mock_secret_read.side_effect = [self.SECRET_DATA]
        with pytest.raises(AssertionError):
            credentials_secret('a-secret', 'a-namespace', 'a-user', 'another-password', verbose=True)
        mock_secret_read.assert_called_once_with('a-secret', 'a-namespace', verbose=True)
        mock_rand_string.assert_not_called()
        mock_secret_create.assert_not_called()

    @mock.patch('nephos.fabric.utils.secret_read')
    @mock.patch('nephos.fabric.utils.secret_create')
    @mock.patch('nephos.fabric.utils.rand_string')
    def test_credentials_secret_baduser(self, mock_rand_string, mock_secret_create, mock_secret_read):
        mock_secret_read.side_effect = [self.SECRET_DATA]
        with pytest.raises(AssertionError):
            credentials_secret('a-secret', 'a-namespace', 'another-user', 'a-password')
        mock_secret_read.assert_called_once_with('a-secret', 'a-namespace', verbose=False)
        mock_rand_string.assert_not_called()
        mock_secret_create.assert_not_called()


class TestCryptoSecret:
    @mock.patch('nephos.fabric.utils.secret_from_file')
    @mock.patch('nephos.fabric.utils.glob')
    def test_crypto_secret(self, mock_glob, mock_secret_from_file):
        mock_glob.side_effect = [['./a_path/a_file.txt']]
        crypto_secret('a-secret', 'a-namespace', './a_dir', 'some_file.txt')
        mock_glob.assert_called_once_with('./a_dir/*')
        mock_secret_from_file.assert_called_once_with(
            secret='a-secret', namespace='a-namespace', key='some_file.txt', filename='./a_path/a_file.txt', verbose=False)

    @mock.patch('nephos.fabric.utils.secret_from_file')
    @mock.patch('nephos.fabric.utils.glob')
    def test_crypto_secret_fail(self, mock_glob, mock_secret_from_file):
        mock_glob.side_effect = [[]]
        with pytest.raises(Exception):
            crypto_secret('a-secret', 'a-namespace', './a_dir', 'some_file.txt')
        mock_glob.assert_called_once_with('./a_dir/*')
        mock_secret_from_file.assert_not_called()


class TestGetPod:
    OPTS = {'core': {'namespace': 'a-namespace'}}

    @mock.patch('nephos.fabric.utils.Executer')
    @mock.patch('nephos.fabric.utils.execute')
    def test_get_pod(self, mock_execute, mock_Executer):
        mock_execute.side_effect = ['a-pod']
        get_pod('a-namespace', 'a-release', 'an-app')
        mock_execute.assert_called_once_with(
            'kubectl get pods -n a-namespace -l "app=an-app,release=a-release" ' +
            '-o jsonpath="{.items[0].metadata.name}"', verbose=False)
        mock_Executer.assert_called_once_with('a-pod', namespace='a-namespace', verbose=False)

    @mock.patch('nephos.fabric.utils.Executer')
    @mock.patch('nephos.fabric.utils.execute')
    def test_get_pod_fail(self, mock_execute, mock_Executer):
        mock_execute.side_effect = ['']
        with pytest.raises(ValueError):
            get_pod('a-namespace', 'a-release', 'an-app', verbose=True)
        mock_execute.assert_called_once_with(
            'kubectl get pods -n a-namespace -l "app=an-app,release=a-release" ' +
            '-o jsonpath="{.items[0].metadata.name}"', verbose=True)
        mock_Executer.assert_not_called()
