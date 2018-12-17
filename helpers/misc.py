from __future__ import print_function

from builtins import input
from getpass import getpass
from os.path import isfile, split
import re
from subprocess import check_output, STDOUT, CalledProcessError
import time

from blessings import Terminal
from pygments import highlight
from pygments.lexers import JsonLexer
from pygments.formatters import TerminalFormatter

t = Terminal()


# Execute commands
def execute(command, verbose=False, show_command=True, show_errors=True):
    if show_command:
        print(t.magenta(command))
    try:
        result = check_output(command,
                              stderr=STDOUT,
                              shell=True)
        decoded = result.decode("utf-8")
        if verbose:
            print(decoded)
        return decoded
    except CalledProcessError as e:
        if show_errors:
            print(t.red("Command failed with CalledProcessError:"))
            print(e.output.decode("utf-8"))


def execute_until_success(command, verbose=False, delay=15):
    res = None
    first_pass = True
    while not res:
        res = execute(command, show_command=first_pass, verbose=verbose and first_pass, show_errors=first_pass)
        first_pass = False
        if not res:
            print(t.red('.'), end='', flush=True)
            time.sleep(delay)
        else:
            if verbose:
                print(res)
            return res


# Input
def input_data(keys, text_append=None):
    data = {}
    input_text = "Input {key}"
    if text_append:
        input_text = input_text + " " + text_append
    for key in keys:
        if isinstance(key, str):
            data[key] = get_response(input_text.format(key=key))
        elif isinstance(key, tuple):
            data[key[0]] = get_response(input_text.format(key=key[0]), **key[1])
    return data


def input_files(keys, text_append=None, clean_key=False):
    data = {}
    input_text = "Input {key}"
    if text_append:
        input_text = input_text + " " + text_append
    for key in keys:
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
                key = re.sub('[^0-9a-zA-Z_.\-]+', '_', dirty_key)
                if key != dirty_key:
                    print(t.yellow('Replaced ') + dirty_key + t.yellow(' with ') + key)
        with open(filename, 'rb') as f:
            data[key] = f.read()
    return data


def get_response(question, permitted_responses=(), sensitive=False):
    print(t.yellow(question))
    if permitted_responses:
        print(t.cyan("Permitted responses: " + str(permitted_responses)))
    responded = 0
    while responded == 0:
        if sensitive:
            response = getpass('Password:')
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


# Display
def pretty_print(string):
    print(highlight(string, JsonLexer(), TerminalFormatter()))
