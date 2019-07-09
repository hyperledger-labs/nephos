from string import ascii_letters, digits, punctuation
from subprocess import CalledProcessError
from unittest.mock import call, patch

from nephos.helpers.misc import (
    execute,
    execute_until_success,
    input_files,
    get_response,
    pretty_print,
    rand_string,
)


class TestExecute:
    @patch("nephos.helpers.misc.check_output")
    @patch("nephos.helpers.misc.logging")
    def test_execute(self, mock_log, mock_check_output):
        execute("ls")
        mock_log.info.assert_called_once()
        mock_log.info.assert_called_with("ls")
        mock_log.debug.assert_called_once()
        mock_check_output.assert_called_once()
        mock_check_output.assert_called_with("ls", shell=True, stderr=-2)

    @patch("nephos.helpers.misc.check_output")
    @patch("nephos.helpers.misc.logging")
    def test_execute_error(self, mock_log, mock_check_output):
        # Add some side effects
        mock_check_output.side_effect = CalledProcessError(
            cmd="lst",
            returncode=127,
            output="/bin/sh: lst: command not found".encode("ascii"),
        )
        execute("lst")
        # First check_output
        mock_check_output.assert_called_once()
        mock_check_output.assert_called_with("lst", shell=True, stderr=-2)
        # Then log
        mock_log.info.assert_called_with("lst")
        mock_log.error.assert_has_calls(
            [
                call("Command failed with CalledProcessError:"),
                call("/bin/sh: lst: command not found"),
            ]
        )


class TestExecuteUntilSuccess:
    @patch("nephos.helpers.misc.execute")
    @patch("nephos.helpers.misc.print")
    @patch("nephos.helpers.misc.logging")
    def test_execute(self, mock_log, mock_print, mock_execute):
        mock_execute.side_effect = [
            (None, "error"),
            (None, "error"),
            ("<h1>SomeWebsite</h1>", None),
        ]
        execute_until_success("curl example.com", delay=0)
        mock_print.assert_has_calls([call(".", end="", flush=True)] * 2)
        mock_log.info.assert_has_calls([call("<h1>SomeWebsite</h1>")])
        mock_execute.assert_has_calls([call("curl example.com")] * 2)


class TestInputFiles:
    files = ["./some_folder/some_file&.txt", "./another_file.txt"]

    @patch("nephos.helpers.misc.open")
    @patch("nephos.helpers.misc.isfile")
    @patch("nephos.helpers.misc.get_response")
    @patch("nephos.helpers.misc.logging")
    def test_input_files(self, mock_log, mock_get_response, mock_isfile, mock_open):
        mock_isfile.side_effect = [True]
        mock_get_response.side_effect = [self.files[0]]
        data = input_files(("hello",))
        mock_log.warning.assert_not_called()
        mock_get_response.assert_called_with("Input hello")
        mock_isfile.assert_called_with(self.files[0])
        mock_open.assert_called_with(self.files[0], "rb")
        assert data.keys() == {"hello"}

    @patch("nephos.helpers.misc.open")
    @patch("nephos.helpers.misc.isfile")
    @patch("nephos.helpers.misc.get_response")
    @patch("nephos.helpers.misc.logging")
    def test_input_files_multiple(
        self, mock_log, mock_get_response, mock_isfile, mock_open
    ):
        mock_isfile.side_effect = [True, True]
        mock_get_response.side_effect = self.files
        data = input_files(("hello", "goodbye"))
        mock_log.warning.assert_not_called()
        mock_get_response.assert_has_calls([call("Input hello"), call("Input goodbye")])
        mock_isfile.assert_has_calls([call(self.files[0]), call(self.files[1])])
        mock_open.assert_any_call(self.files[0], "rb")
        mock_open.assert_any_call(self.files[1], "rb")
        assert data.keys() == {"hello", "goodbye"}

    @patch("nephos.helpers.misc.open")
    @patch("nephos.helpers.misc.isfile")
    @patch("nephos.helpers.misc.get_response")
    @patch("nephos.helpers.misc.logging")
    def test_input_files_mistake(
        self, mock_log, mock_get_response, mock_isfile, mock_open
    ):
        mock_isfile.side_effect = [False, True]
        mock_get_response.side_effect = [self.files[0] + "OOPS", self.files[0]]
        data = input_files(("hello",))
        mock_log.warning.assert_called_once_with(
            f"{self.files[0] + 'OOPS'} is not a file"
        )
        mock_get_response.assert_has_calls([call("Input hello"), call("Input hello")])
        mock_isfile.assert_has_calls(
            [call(self.files[0] + "OOPS"), call(self.files[0])]
        )
        mock_open.assert_called_with(self.files[0], "rb")
        assert data.keys() == {"hello"}

    @patch("nephos.helpers.misc.open")
    @patch("nephos.helpers.misc.isfile")
    @patch("nephos.helpers.misc.get_response")
    @patch("nephos.helpers.misc.logging")
    def test_input_files_cleankey(
        self, mock_log, mock_get_response, mock_isfile, mock_open
    ):
        mock_isfile.side_effect = [True]
        mock_get_response.side_effect = [self.files[0]]
        data = input_files((None,), clean_key=True)
        mock_log.warning.assert_called_once_with(
            "Replaced some_file&.txt with some_file_.txt"
        )
        mock_get_response.assert_called_with("Input None")
        mock_isfile.assert_called_with(self.files[0])
        mock_open.assert_called_with(self.files[0], "rb")
        assert data.keys() == {"some_file_.txt"}


class TestGetResponse:
    @patch("nephos.helpers.misc.input")
    @patch("nephos.helpers.misc.logging")
    def test_get_response(self, mock_log, mock_input):
        mock_input.side_effect = ["An answer"]
        answer = get_response("A question")
        mock_input.assert_called_once()
        mock_log.info.assert_called_with("A question")
        assert answer == "An answer"

    @patch("nephos.helpers.misc.getpass")
    @patch("nephos.helpers.misc.input")
    @patch("nephos.helpers.misc.logging")
    def test_get_response_password(self, mock_log, mock_input, mock_getpass):
        mock_getpass.side_effect = ["A password"]
        answer = get_response("A question", sensitive=True)
        mock_input.assert_not_called()
        mock_log.info.assert_called_with("A question")
        mock_getpass.assert_called_once_with("Password:")
        assert answer == "A password"

    @patch("nephos.helpers.misc.input")
    @patch("nephos.helpers.misc.logging")
    def test_get_response_options(self, mock_log, mock_input):
        mock_input.side_effect = ["mistake", "y"]
        get_response("A question", ("y", "n"))
        mock_input.assert_has_calls([call()] * 2)
        mock_log.info.assert_has_calls(
            [call("A question"), call("Permitted responses: ('y', 'n')")]
        )
        mock_log.error.assert_called_with("Invalid response, try again!")


class TestPrettyPrint:
    def test_pretty_print(self):
        assert (
            pretty_print('{"some": "json"}')
            == '{\x1b[34;01m"some"\x1b[39;49;00m: \x1b[33m"json"\x1b[39;49;00m}\n'
        )


class TestRandString:
    def test_rand_string(self):
        a_string = rand_string(16)
        assert len(a_string) == 16
        assert set(ascii_letters + digits).intersection(set(a_string))
        assert not set(punctuation).intersection(set(a_string))

    def test_rand_string_(self):
        a_string = rand_string(24)
        assert len(a_string) == 24
