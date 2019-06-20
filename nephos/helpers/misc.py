from __future__ import print_function

import random
from builtins import input
from getpass import getpass
from os.path import isfile, split
import re
from string import ascii_letters, digits
from subprocess import check_output, STDOUT, CalledProcessError
import time
import logging

from blessings import Terminal
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter

t = Terminal()


def execute(command):
    """Execute an arbitrary command line command.

    Args:
        command (str): Command to execute.
    Returns:
        tuple: 2-tuple of execution info:
        1) result of the command, if successful, None if not;
        2) and error, if command failed, None if not.
    """
    logging.info(t.magenta(command))
    try:
        # TODO: Can we do this with a different command than check_output (Bandit security issue)
        result = check_output(command, stderr=STDOUT, shell=True)
        decoded = result.decode("utf-8")
        logging.debug(decoded)
        return decoded, None
    except CalledProcessError as e:
        error_text = e.output.decode("utf-8")
        logging.error(t.red("Command failed with CalledProcessError:"))
        logging.error(error_text)
        return None, error_text


def execute_until_success(command, delay=15):
    """Execute a command until it is successful.

    Args:
        command (str): Command to execute.
        delay (int): Delay in seconds between each unsuccessful attempt.

    Returns:
        str: result of the command
    """
    res = None
    while not res:
        res, err = execute(
            command,
        )
        if err:
            print(t.red("."), end="", flush=True)
            time.sleep(delay)
        else:
            logging.info(res)
            return res


def input_files(keys, clean_key=False):
    """Read a set of filenames and return data from them.

    Args:
        keys (Iterable): Tuple of keys
        clean_key (bool): Do we clean the key to replace non-alphanumeric symbols with an underscore? False by default.

    Returns:
        dict: Data from each file assigned to its relevant key.
    """
    data = {}
    input_text = "Input {key}"
    for key in keys:
        # TODO: This could be its own function.
        is_file = False
        while not is_file:
            filename = get_response(input_text.format(key=key))
            is_file = isfile(filename)
            if not is_file:
                logging.warning(f"{filename} is not a file")
        if key is None:
            key = split(filename)[1]
            if clean_key:
                dirty_key = key
                key = re.sub(r"[^0-9a-zA-Z_.\-]+", "_", dirty_key)
                if key != dirty_key:
                    logging.warning(t.yellow("Replaced ") + dirty_key + t.yellow(" with ") + key)
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
    logging.info(t.yellow(question))
    if permitted_responses:
        logging.info(t.cyan("Permitted responses: " + str(permitted_responses)))
    responded = 0
    while responded == 0:
        if sensitive:
            response = getpass("Password:")
        else:
            response = input()
        # Check type of response
        if response in permitted_responses or not permitted_responses:
            # Response is among possible responses (or any response is permitted)
            responded = 1
        # Otherwise we ping the user to input a response
        if not responded:
            logging.error(t.red("Invalid response, try again!"))
    return response


def pretty_print(string):
    """Pretty print a JSON string.

    Args:
        string (str): String we want to pretty print.
    """
    return highlight(string, JsonLexer(), TerminalFormatter())


def rand_string(length):
    """Create random alphanumeric string (useful for passwords).

    Args:
        length (int): Length of random string.

    Returns:
        str: Alphanumeric string.
    """
    return "".join(random.choice(ascii_letters + digits) for _ in range(length))
