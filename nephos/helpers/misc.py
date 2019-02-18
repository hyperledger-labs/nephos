from __future__ import print_function

import random
from builtins import input
from getpass import getpass
from os.path import isfile, split
import re
from string import ascii_letters, digits
from subprocess import check_output, STDOUT, CalledProcessError
import time

from blessings import Terminal
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter

t = Terminal()


def execute(command, verbose=False, show_command=True, show_errors=True):
    """Execute an arbitrary command line command.

    Args:
        command (str): Command to execute.
        verbose (bool): Verbosity. False by default.
        show_command (bool): Do we display the command? True by default.
        show_errors (bool): Do we display errors? True by default.

    Returns:
        tuple: 2-tuple of execution info:
        1) result of the command, if successful, None if not;
        2) and error, if command failed, None if not.
    """
    if show_command:
        print(t.magenta(command))
    try:
        result = check_output(command, stderr=STDOUT, shell=True)
        decoded = result.decode("utf-8")
        if verbose:
            print(decoded)
        return decoded, None
    except CalledProcessError as e:
        error_text = e.output.decode("utf-8")
        if show_errors:
            print(t.red("Command failed with CalledProcessError:"))
            print(error_text)
        return None, error_text


def execute_until_success(command, verbose=False, delay=15):
    """Execute a command until it is successful.

    Args:
        command (str): Command to execute.
        verbose (bool): Verbosity. False by default.
        delay (int): Delay in seconds between each unsuccessful attempt.

    Returns:
        str: result of the command
    """
    res = None
    first_pass = True
    while not res:
        res, _ = execute(
            command,
            show_command=first_pass,
            verbose=verbose and first_pass,
            show_errors=first_pass,
        )
        first_pass = False
        if not res:
            print(t.red("."), end="", flush=True)
            time.sleep(delay)
        else:
            if verbose:
                print(res)
            return res


# TODO: Do we really need the text append feature?
def input_files(keys, text_append=None, clean_key=False):
    """Read a set of filenames and return data from them.

    Args:
        keys (tuple): Tuple of keys
        text_append (str): Text to append to the key request.
        clean_key (bool): Do we clean the key to replace non-alphanumeric symbols with an underscore? False by default.

    Returns:
        dict: Data from each file assigned to its relevant key.
    """
    data = {}
    input_text = "Input {key}"
    if text_append:
        input_text = input_text + " " + text_append
    for key in keys:
        # TODO: This could be its own function.
        is_file = False
        while not is_file:
            filename = get_response(input_text.format(key=key))
            is_file = isfile(filename)
            if not is_file:
                print("{} is not a file".format(filename))
        if key is None:
            key = split(filename)[1]
            if clean_key:
                dirty_key = key
                key = re.sub("[^0-9a-zA-Z_.\-]+", "_", dirty_key)
                if key != dirty_key:
                    print(t.yellow("Replaced ") + dirty_key + t.yellow(" with ") + key)
        with open(filename, "rb") as f:
            data[key] = f.read()
    return data


def get_response(question, permitted_responses=(), sensitive=False):
    """Get response from user.

    Args:
        question: What do we want to obtain from the user?
        permitted_responses: What responses do we allow?
        sensitive: Is the information sensitive (e.g. a password)?

    Returns:
        str: Response from user.
    """
    print(t.yellow(question))
    if permitted_responses:
        print(t.cyan("Permitted responses: " + str(permitted_responses)))
    responded = 0
    while responded == 0:
        if sensitive:
            response = getpass("Password:")
        else:
            response = input()
        # Check type of response
        if response in permitted_responses:
            # Response is among possible responses
            responded = 1
        elif not permitted_responses:
            # Any response permitted
            responded = 1
        # Otherwise we ping the user to input a response
        if not responded:
            print(t.red("Invalid response, try again!"))
    return response


def pretty_print(string):
    """Pretty print a JSON string.

    Args:
        string (str): String we want to pretty print.
    """
    print(highlight(string, JsonLexer(), TerminalFormatter()))


def rand_string(length):
    """Create random alphanumeric string (useful for passwords).

    Args:
        length (int): Length of random string.

    Returns:
        str: Alphanumeric string.
    """
    return "".join(random.choice(ascii_letters + digits) for _ in range(length))
