#!/usr/bin/env python3

# Copyright (c) 2018-2020 MobileCoin Inc.

import argparse
import qrcode
import sys
import os.path
import traceback
import json
import time
import re
import grpc

# provides command line progress indicator
from halo import Halo

try:
    import readline
except ImportError:
    # readline not required on Windows
    pass

from mob_client import mob_client

# this regular expression matches valid base 58 strings
b58re = re.compile(
    r'[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*')

# Keep track of known account aliases along with their root entropy
# example: {"a":{"entropy":"5626b806e7736e568f67731e8a26d8e581c32f0aaffdc643fbbdab72a1eb5708"},}
known_accounts = {}


""" Error handling.
"""


class ClientError(Exception):
    pass


""" Parse a known account
"""


def parse_account(account_string):
    account_key = account_string.lower().strip()
    if not account_key in known_accounts:
        raise ClientError(
            'failed to parse a known accout from "{}"'.format(account_string))
    return known_accounts[account_key]


""" Parse a positive integer index
"""


def parse_uint(index_string):
    try:
        index = int(index_string.lower().strip())
        assert (index >= 0)
        return index
    except Exception:
        raise ClientError(
            'failed to parse a positive integer from "{}"'.format(index_string))


""" Parse a subaddress of the form "account/#"
"""


def parse_subaddress(subaddress_string):
    parts = subaddress_string.lower().strip().split('/')
    if len(parts) != 2:
        raise ClientError(
            'failed to parse subaddress from "{}"'.format(subaddress_string))
    account = parse_account(parts[0])
    index = parse_uint(parts[1])
    return account, index


""" Parse an index range of the form "[#,#]"
"""


def parse_index_range(index_range_string):
    if index_range_string[0] != '[' or index_range_string[-1] != ']':
        raise ClientError(
            'failed to parse index range from "{}"'.format(index_range_string))
    else:
        indices = []
        for index_string in index_range_string[1:-1].split(','):
            index = parse_uint(index_string)
            indices.append(index)
        return {"first_index": indices[0], "last_index": indices[1]}


""" Returns the credentials for an account
"""


def get_account_credentials(account):
    if "entropy" in account:
        return client.get_account_key(bytes.fromhex(account["entropy"]))
    else:
        raise ClientError('account "{}" is malformed'.format(account["name"]))


""" Add a QR code to the buffer
"""


def get_qrcode(b58code):
    qr = qrcode.QRCode(border=0)
    qr.add_data(b58code)
    qr.make()
    #qr.print_ascii(out=buffer)
    result = '\n\nqrcode content: {}\n\n'.format(b58code)
    return result


""" Loads global variable known_accounts from a json file.
    Usage: load (opt) <file>
"""


def load_accounts(args):
    try:
        if args:
            json_file = args[0]
        else:  # allow lazy load for default
            json_file = "accounts.json"
        if not os.path.isfile(json_file):
            json_file += ".json"  # allow user to omit extension
        with open(json_file) as f:
            known_accounts.update(json.load(f))
        # add names for later use
        for key, account in known_accounts.items():
            known_accounts[key]["name"] = key
        return "Loaded {} accounts.".format(len(known_accounts))
    except ClientError as e:
        return 'client error:\n{}:{}'.format(type(e).__name__, e.args)
    except grpc.RpcError as e:
        return 'mobilecoind error:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())
    except Exception as e:
        return 'Error loading file "{}":\n{}:{}\n{}'.format(
            args[0] if args else "(empty)", type(e).__name__, e.args, traceback.format_exc())


""" List known accounts.
    Usage: accounts
"""


def list_accounts(args):
    try:
        if len(known_accounts) == 0:
            return "There are no known accounts."
        str = ""
        for (i, account) in enumerate(known_accounts):
            monitor_id_list = []
            if "monitors" in account:
                monitor_id_list = account["monitors"]
                for id in monitor_id_list:
                    status = client.get_monitor_status(id)
                    str += '#{} : account "{}" '.format(i, account["name"])
                    str += 'is monitoring subaddress range [{},{}]\n'.format(
                        status.first_index, status.last_index)
            else:
                str += '#{} : account "{}" is known, but has no monitors.\n'.format(
                    i, known_accounts[account]["name"])
        str = str[0:-1]  # remove the final '\n'
        return str
    except ClientError as e:
        return 'client error:\n{}:{}'.format(type(e).__name__, e.args)
    except grpc.RpcError as e:
        return 'mobilecoind error:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())
    except Exception as e:
        return 'Error listing accounts:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())


""" Monitor incoming transactions for a set of subaddresses for a known alias.
    Usage: monitor <account> (opt)<[min,max]>
"""


def add_monitor(args):
    try:
        account = parse_account(args[0])
        credentials = get_account_credentials(account)
        id = b''  # empty bytes
        if len(args) == 2:
            index_range = parse_index_range(args[1])
            id = client.add_monitor(
                credentials, first_subaddress=index_range['first_index'], num_subaddresses=index_range['last_index'])
        else:
            id = client.add_monitor(credentials)
        account["monitors"] = [id]
        status = client.get_monitor_status(id)
        str = 'account "{}" '.format(account["name"])
        str += 'added a monitor for subaddress range [{},{}]'.format(
            status.first_subaddress, status.num_subaddresses)
        return str
    except ClientError as e:
        return 'client error:\n{}:{}'.format(type(e).__name__, e.args)
    except grpc.RpcError as e:
        return 'mobilecoind error:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())
    except Exception as e:
        return 'Error adding monitor:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())


""" List active monitors.
    Usage: monitors
"""


def list_monitors(args):
    try:
        monitor_id_list = client.get_monitor_list()
        result = ('Account Monitor List:\n')
        for (i, id) in enumerate(monitor_id_list):
            status = client.get_monitor_status(id)
            str = '#{} [{}]: account {} is monitoring subaddress range [{},{}]'
            account = account_from_monitor_id
            result += (str.format(
                i, id.hex(), account["name"], status.first_index, status.last_index))
            return result
    except ClientError as e:
        return 'client error:\n{}:{}'.format(type(e).__name__, e.args)
    except grpc.RpcError as e:
        return 'mobilecoind error:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())
    except Exception as e:
        return 'Error listing monitors:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())


""" Returns the balance for a subaddress.
    Usage: balance <account/#>
"""


def check_balance(args):
    try:
        account, index = parse_subaddress(args[0])
        credentials = get_account_credentials(account)
        monitor_id = client.get_monitor_id(credentials, index)
        balance = client.get_balance(monitor_id, index)
        monitor_last_block = client.get_monitor_status(monitor_id).next_block
        block_count = client.get_ledger_info()[0]
        if block_count > 0:
            subaddress_str = '{}/{}'.format(account["name"], index)
            return '{} has {} pMOB @ block {} of {} available'.format(
                args[0], balance, monitor_last_block, block_count)
        else:
            raise ClientError('no ledger blocks have been downloaded')
    except ClientError as e:
        return 'client error:\n{}:{}'.format(type(e).__name__, e.args)
    except grpc.RpcError as e:
        return 'mobilecoind error:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())
    except Exception as e:
        return 'Error checking balance:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())


""" Send funds between accounts
    Usage: transfer <value> <from_account/#> <to_account/#>
"""


def transfer(args):
    try:
        # Get sender info and monitor
        value = parse_uint(args[0])
        from_account, from_index = parse_subaddress(args[1])
        from_credentials = get_account_credentials(from_account)
        from_monitor = client.get_monitor_id(from_credentials, from_index)

        # Get recipient info and monitor
        to_account, to_index = parse_subaddress(args[2])
        to_credentials = get_account_credentials(to_account)
        to_monitor = client.get_monitor_id(to_credentials, to_index)
        target_address = client.get_public_address(to_monitor, to_index) 

        # Construct the transaction
        tx_list = client.get_unspent_tx_output_list(from_monitor, from_index) 
        outlays = [{'value': value, 'receiver': target_address}]                                                                       
        tx_proposal = client.generate_tx(from_monitor, from_index, tx_list, outlays)                                                                 
        
        # Submit the transaction
        sender_tx_receipt = client.submit_tx(tx_proposal)
        return 'Transaction submitted with key_images: {}'.format(
            sender_tx_receipt.key_image_list)
    except ClientError as e:
        return 'client error:\n{}:{}'.format(type(e).__name__, e.args)
    except grpc.RpcError as e:
        return 'mobilecoind error:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())
    except Exception as e:
        return 'Error transferring funds:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())


""" Return the status of the most recent transaction for an account
    Usage: status <account>
"""
TRANSACTION_STATUS = {
    0: "Unknown",
    1: "Pending",
    2: "Verified",
    3: "TombstoneBlockExceeded",
}


def status(args):
    try:
        account = parse_account(args[0])
        if "sender_tx_receipt" in account:
            status = client.get_tx_status_as_sender(
                account["sender_tx_receipt"])
        elif "recipient_tx_receipt" in account:
            status = client.get_tx_status_as_receiver(
                account["recipient_tx_receipt"])
        else:
            return 'No transaction has been sent.'
        return "Transaction status is: " + TRANSACTION_STATUS[status]
    except ClientError as e:
        return 'client error:\n{}:{}'.format(type(e).__name__, e.args)
    except grpc.RpcError as e:
        return 'mobilecoind error:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())
    except Exception as e:
        return 'Error checking status:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())


""" Create and display a withdrawal QR code
    Usage: create-withdrawal <value> <from_account/#>
"""


def create_withdrawal(args):
    try:
        value = parse_uint(args[0])
        from_account, from_index = parse_subaddress(args[1])
        from_credentials = get_account_credentials(from_account)
        sender = client.get_sender(from_credentials, from_index)
        monitor_id = client.get_monitor_id(from_credentials, from_index)
        all_outputs = client.get_tx_output_list(monitor_id, from_index)
        spendable_outputs = client.get_spendable_outputs(sender, all_outputs)
        to_credentials = client.generate_entropy()
        receiver = client.get_receiver(to_credentials)
        sender_tx_receipt, receiver_tx_receipt = client.send_payment(
            sender, spendable_outputs, receiver, value)[0, 1]
        from_account["sender_tx_receipt"] = sender_tx_receipt
        del from_account["receiver_tx_receipt"]  # clear any old tx
        tx_public_key = receiver_tx_receipt.tx_public_key
        result = ('Transaction submitted with key_image: {}'.format(
            sender_tx_receipt.key_image))
        status = status(args[1])
        while(status == 0):
            time.sleep(1)
            status = status(args[1])
        assert(status == 1)
        b58_code = client.get_transfer_code(to_credentials, tx_public_key)
        result += _qrcode(b58code)
        result += ("Scan this code to complete your withdrawal.")
    except ClientError as e:
        result += ('client error:\n{}:{}'.format(type(e).__name__, e.args))
    except grpc.RpcError as e:
        result += ('mobilecoind error:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc()))
    except Exception as e:
        result += ('Error creating withdrawal:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc()))


""" Withdraw funds to a subaddress
    Usage: withdraw <b58code> <to_account/#>
"""


def withdraw(args):
    try:
        if not b58re.match(args[0]):
            raise ClientError('invalid base58 code: "{}"'.format(args[0]))
        to_account, to_index = parse_subaddress(args[1])
        from_credentials, tx_public_key, memo = client.read_transfer_code(
            b58_code)
        txo = client.get_tx_output(tx_public_key)
        value = txo.value
        sender = client.get_sender(from_credentials)
        to_credentials = get_account_credentials(to_account)
        receiver = client.get_receiver(to_credentials, to_index)
        receiver_tx_receipt = client.send_payment(
            sender, [txo], receiver, value)[1]
        to_account["receiver_tx_receipt"] = receiver_tx_receipt
        del to_account["sender_tx_receipt"]  # clear any old tx
        result = ('Transaction submitted with tx_public_key: {}'.format(
            receiver_tx_receipt.tx_public_key))
    except ClientError as e:
        result += ('client error:\n{}:{}'.format(type(e).__name__, e.args))
    except grpc.RpcError as e:
        result += ('mobilecoind error:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc()))
    except Exception as e:
        result += ('Error withdrawing funds:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc()))


""" create and display a deposit QR code
    Usage: create-deposit <value> <to_account/#>
"""


def create_deposit(args):
    try:
        value = parse_uint(args[0])
        to_account, to_index = parse_subaddress(args[1])
        to_credentials = get_account_credentials(to_account)
        receiver = client.get_receiver(to_credentials, to_index)
        b58_code = client.get_request_code(receiver, value)
        result = _qrcode(b58code)
        result += ("Scan this code to complete your deposit.")
    except ClientError as e:
        result += ('client error:\n{}:{}'.format(type(e).__name__, e.args))
    except grpc.RpcError as e:
        result += ('mobilecoind error:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc()))
    except Exception as e:
        result += ('Error creating deposit:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc()))


""" deposit funds from a subaddress
    Usage: deposit <b58code> <from_account/#>
"""


def deposit(args):
    try:
        if not b58re.match(args[0]):
            raise ClientError('invalid base58 code: "{}"'.format(args[0]))
        receiver, value, memo = client.read_request_code(b58_code)
        from_account, from_index = parse_subaddress(args[1])
        from_credentials = get_account_credentials(from_account)
        sender = client.get_sender(from_credentials, from_index)
        monitor_id = client.get_monitor_id(from_credentials, from_index)
        all_outputs = client.get_tx_output_list(monitor_id, from_index)
        spendable_outputs = client.get_spendable_outputs(sender, all_outputs)
        sender_tx_receipt = client.send_payment(
            sender, spendable_outputs, receiver, value)[0]
        from_account["sender_tx_receipt"] = sender_tx_receipt
        del from_account["receiver_tx_receipt"]  # clear any old tx
        return 'Transaction submitted with key_image: {}'.format(
            sender_tx_receipt.key_image)
    except ClientError as e:
        return 'client error:\n{}:{}'.format(type(e).__name__, e.args)
    except grpc.RpcError as e:
        return 'mobilecoind error:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())
    except Exception as e:
        return 'Error depositing funds:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())



""" Return the status of the most recent transaction
    Usage: test <msec>
"""


def mobilecoind_test(args):
    try:
        delay_msec = parse_uint(args[0])
        start = client.get_ledger_info()
        time.sleep(0.001 * delay_msec)
        end = client.get_ledger_info()
        new_blocks = end[0] - start[0]
        new_txos = end[1] - start[1]
        if new_blocks > 0:
            result = ('downloaded {0:5d} new blocks     ( {1:5d} per second )\n'.format(
                new_blocks, new_blocks / (0.001 * delay_msec)))
            result += ('downloaded {0:5d} new txos       ( {1:5d} per second )\n'.format(
                new_txos, new_txos / (0.001 * delay_msec)))
            return result
        else:
            return 'No new blocks processed in {} milliseconds.'.format(delay_msec)
    except ClientError as e:
        return 'client error:\n{}:{}'.format(type(e).__name__, e.args)
    except grpc.RpcError as e:
        return 'mobilecoind error:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())
    except Exception as e:
        return 'Error testing mobilecoind:\n{}:{}\n{}'.format(
            type(e).__name__, e.args, traceback.format_exc())


""" Display command list
"""


def help(args):
    command_width = 20
    syntax_width = 52
    use_width = 50
    help_width = 3 + command_width + syntax_width + use_width
    row_format = '* {:<%ds}{:<%ds}{:<%ds}*' % (
        command_width, syntax_width, use_width)
    result = '*' * help_width + '\n'
    result += row_format.format("Command", "Syntax", "Use") + '\n'
    result += row_format.format("-" * command_width,
                                 "-" * syntax_width, "-" * use_width)
    unique_cmds = {}
    for cmd in dispatch.keys():
        key = dispatch[cmd]["help"]
        if key in unique_cmds.keys():
            if len(cmd) > len(unique_cmds[key]):
                unique_cmds[key] = cmd
        else:
            unique_cmds[key] = cmd
    cmds_to_display = {}
    for key in unique_cmds.keys():
        cmd = unique_cmds[key]
        cmds_to_display[cmd] = {dispatch[cmd]["usage"], dispatch[cmd]["help"]}
    for cmd in sorted(cmds_to_display):
        result += '\n'
        result += (row_format.format(
            cmd, dispatch[cmd]["usage"], dispatch[cmd]["help"]))
    result += '\n' + '*' * help_width
    return result


""" Command table
"""
dispatch = {
    "help": {"fn": help, "args": [0],
             "usage": "",
             "help": "display a list of commands"},
    "load": {"fn": load_accounts, "args": [0, 1],
             "usage": "load (opt)<file>",
             "help": "load a table of known accounts from a file"},
    "monitor": {"fn": add_monitor, "args": [1, 2],
                "usage": "monitor <account> (opt)<[min,max]>",
                "help": "monitor txos for a set of subaddresses"},
    "balance": {"fn": check_balance, "args": [1],
                "usage": "balance <account/#>",
                "help": "return the balance for a subaddress"},
    "transfer": {"fn": transfer, "args": [3],
                 "usage": "transfer <value> <from_account/#> <to_account/#>",
                 "help": "transfer funds between subaddresses"},
    "status": {"fn": status, "args": [1],
               "usage": "status <account>",
               "help": "print the status of the last transfer"},
    "create-withdrawal": {"fn": create_withdrawal, "args": [2],
                          "usage": "create-withdrawal <value> <from_account/#>",
                          "help": "create and display a withdrawal QR code"},
    "withdraw": {"fn": withdraw, "args": [2],
                 "usage": "withdraw <b58code> <to_account/#>",
                 "help": "withdraw funds to a subaddress"},
    "create-deposit": {"fn": create_deposit, "args": [2],
                       "usage": "create-deposit <value> <to_account/#>",
                       "help": "create and display a deposit QR code"},
    "deposit": {"fn": deposit, "args": [2],
                "usage": "deposit <b58code> <from_account/#>",
                "help": "deposit funds from a subaddress"},
    "test": {"fn": mobilecoind_test, "args": [1],
             "usage": "test <msec>",
             "help": "measure and display mobilecoind performance"},
    "monitors": {"fn": list_monitors, "args": [0],
                 "usage": "",
                 "help": "list active monitors"},
    "accounts": {"fn": list_accounts, "args": [0],
                 "usage": "",
                 "help": "list known accounts"},
}


def add_cmd_aliases(cmd, aliases):
    for cmd_alias in aliases:
        dispatch[cmd_alias] = dispatch[cmd]


add_cmd_aliases("accounts", ["ls", "list"])
add_cmd_aliases("help", ["?"])
add_cmd_aliases("transfer", ["move", "mv", "send", "pay"])
add_cmd_aliases("status", ["check"])
add_cmd_aliases("balance", ["b"])
add_cmd_aliases("monitor", ["m", "add"])

""" Interaction loop with mob_client
"""


def run(client):
    spinner = Halo(text=' processing... ', spinner='dots')
    while True:
        print('# ', end='')
        cmd = input().lower().strip().split(' ')
        if not cmd[0]:
            continue
        elif cmd[0] in ('exit', 'quit', 'q'):
            break
        elif cmd[0] in dispatch.keys():
            fn = dispatch[cmd[0]]["fn"]
            args = cmd[1:]
            expected_args_len_list = dispatch[cmd[0]]["args"]
            if not len(args) in expected_args_len_list:
                print('Usage: ' + dispatch[cmd[0]]["usage"])
            elif not fn:
                pass
            else:
                spinner.start()
                result = fn(args)
                spinner.stop()
                print(result)
        else:
            print('Unknown command. Enter "help" to display a list of commands.')


""" Parse the arguments and generate the mob_client
"""
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Connect to a mobilecoind daemon')
    parser.add_argument('daemon', help='Address and port of daemon', type=str)
    parser.add_argument('--ssl', help='Use SSL', action='store_true')
    args = parser.parse_args()

    client = mob_client(args.daemon, args.ssl)
    run(client)
