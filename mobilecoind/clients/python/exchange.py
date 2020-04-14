# Copyright (c) 2018-2020 MobileCoin Inc.

import qrcode
import sys
import os.path
import traceback
import json
import time
import re
import grpc

import cmd

from mob_client import mob_client


def mob_command(func):
    """ Decorator to handle possible errors
    """
    def wrapper(session, *args, **kwargs):
        try:
            if args and args[0] == '':
                success_str = func(session)
            else:
                success_str = func(session, *args, **kwargs)
            # FIXME: Use Halo decorator to get cool spinners
            print(success_str)
        except ClientError as e:
            print("Client error:\n{}:{}".format(type(e).__name__, e.args))
        except grpc.RpcError as e:
            print("mobilecoind error:\n{}:{}\n{}".format(
                type(e).__name__, e.args, traceback.format_exc()))
            print("Please try again.")
        except Exception as e:
            print("Unexpected error {}:\n{}:{}\n{}".format(
                args[0] if args else "(empty)",
                type(e).__name__, e.args, traceback.format_exc()))
            session.do_help(*args)

    return wrapper


class ClientError(Exception):
    """ Error handling.
    """
    pass


class Session(cmd.Cmd):
    """ Encapsulates a wallet session

    known_accounts: Keep track of known account aliases along with their root entropy
    # example: {"a":{"entropy":"5626b806e7736e568f67731e8a26d8e581c32f0aaffdc643fbbdab72a1eb5708"},}

    """
    intro = 'Welcome to the MobileCoin Python Client example. Type help or ? to list commands.'
    prompt = '# '

    known_accounts = {}
    client = None

    def __init__(self, daemon, ssl):
        """ Initialize client session.
        """
        self.client = mob_client(daemon, ssl)
        super().__init__()

    # Commands, with special structure for use by the Cmd class.
    # Handle argument parsing to forward on to @mob_command-wrapped impls below.

    def do_quit(self, s):
        '''quit - quit the program'''
        sys.exit(0)

    def do_load(self, args):
        '''load (optional)<file> - loads a table of known accounts from a json file'''
        self.load_accounts(args)

    def do_accounts(self, _args):
        '''list-accounts - list known accounts'''
        self.list_accounts()

    def do_monitor(self, args):
        '''monitor <account> (optional)<[min,max]> - Monitor txos for a set of subaddresses'''
        if len(self.known_accounts) == 0:
            print("You have not yet loaded any accounts to monitor")
            return
        parts = args.split()
        if len(parts) == 0 or len(parts) > 2:
            print(
                "Please provide one account to monitor and optionally a subaddress range."
            )
            return
        account = self.known_accounts[parts[0]]
        index_range = None
        if len(args) == 2:
            index_range = self.parse_index_range(parts[1])
        self.add_monitor(account, index_range)

    def do_monitors(self, _args):
        '''list-monitors - list active monitors'''
        self.list_monitors()

    def do_balance(self, args):
        '''balance <account> <index> - get the balance for a subaddress.
                                       Defaults to subaddress 0.
        '''
        parts = args.split()
        if len(parts) == 0 or len(parts) > 2:
            print("Please provide account and optional index")
            return
        index = int(parts[1]) if len(parts) > 1 else 0
        if parts[0] not in self.known_accounts:
            print("We are not tracking that account.")
            return
        self.check_balance(self.known_accounts[parts[0]], index)

    def do_transfer(self, args):
        '''transfer <value> <from_account> <subaddress> <to_account> <subaddress> - Transfer funds between accounts and subaddresses'''
        parts = args.split()
        if len(parts) != 5:
            print(
                "Please provide the params: value from_account subaddress to_account subaddress."
            )
            return
        self.transfer(int(parts[0]), self.known_accounts[parts[1]],
                      int(parts[2]), self.known_accounts[parts[3]],
                      int(parts[4]))

    def do_status(self, args):
        '''status <account> - Print the status of the last transfer for the provided account'''
        parts = args.split()
        if len(parts) != 1:
            print("Please provide exactly one account.")
            return
        self.status(self.known_accounts[parts[0]])

    # Command implementations

    @mob_command
    def load_accounts(self, json_file="accounts.json"):
        """ Loads known_accounts from a json file.
        """
        # allow user to omit extension
        root, ext = os.path.splitext(json_file)
        if not ext:
            json_file += ".json"

        with open(json_file) as f:
            self.known_accounts.update(json.load(f))
        # add names for later use
        for key, account in self.known_accounts.items():
            self.known_accounts[key]["name"] = key
        return "Loaded {} accounts.".format(len(self.known_accounts))

    @mob_command
    def list_accounts(self):
        """ List known accounts.
        """
        if len(self.known_accounts) == 0:
            return "There are no known accounts."
        str = ""
        for account_key, account_data in self.known_accounts.items():
            monitor_id_list = []
            if "monitors" in account_data:
                monitor_id_list = account_data["monitors"]
                for id in monitor_id_list:
                    status = self.client.get_monitor_status(id)
                    str += '#{} : account "{}" '.format(
                        account_key, account_data["name"])
                    str += 'is monitoring subaddress range [{},{}]\n'.format(
                        status.first_block, status.next_block)
            else:
                str += '#{} : account "{}" is known, but has no monitors.\n'.format(
                    account_key, account_data["name"])
        str = str[0:-1]  # remove the final '\n'
        return str

    @mob_command
    def add_monitor(self, account, index_range=None):
        """ Monitor incoming transactions for a set of subaddresses for a known alias.
        """
        credentials = self.get_account_credentials(account)
        id = b''  # empty bytes
        if index_range is not None:
            id = self.client.add_monitor(
                credentials,
                first_subaddress=index_range['first_index'],
                num_subaddresses=index_range['last_index'])
        else:
            id = self.client.add_monitor(credentials)
        account["monitors"] = [id]
        status = self.client.get_monitor_status(id)
        str = 'account "{}" '.format(account["name"])
        str += 'added a monitor for subaddress range [{},{}]'.format(
            status.first_subaddress, status.num_subaddresses)
        return str

    @mob_command
    def list_monitors(self):
        """ List active monitors.
        """
        monitor_id_list = self.client.get_monitor_list()
        result = ('Account Monitor List:\n')
        for (i, id) in enumerate(monitor_id_list):
            status = self.client.get_monitor_status(id)
            str = '#{} [{}]: account {} is monitoring subaddress range [{},{}]'
            # FIXME account = account_from_monitor_id, account["name"]
            result += (str.format(i, id.hex(), id, status.first_block,
                                  status.next_block))
        return result

    @mob_command
    def check_balance(self, account, index):
        """ Returns the balance for a subaddress.
        """
        credentials = self.get_account_credentials(account)
        monitor_id = self.client.get_monitor_id(credentials, index)
        balance = self.client.get_balance(monitor_id, index)
        monitor_last_block = self.client.get_monitor_status(
            monitor_id).next_block
        block_count = self.client.get_ledger_info()[0]
        if block_count > 0:
            subaddress_str = '{}/{}'.format(account["name"], index)
            return '{} has {} pMOB @ block {} of {} available'.format(
                account["name"], balance, monitor_last_block, block_count)
        else:
            raise ClientError('no ledger blocks have been downloaded')

    @mob_command
    def transfer(self, value, from_account, from_index, to_account, to_index):
        """ Send funds between accounts
        Usage: transfer <value> <from_account/#> <to_account/#>
        """
        # Get sender info and monitor
        from_credentials = self.get_account_credentials(from_account)
        from_monitor = self.client.get_monitor_id(from_credentials, from_index)

        # Get recipient info and monitor
        to_credentials = self.get_account_credentials(to_account)
        to_monitor = self.client.get_monitor_id(to_credentials, to_index)
        target_address = self.client.get_public_address(to_monitor, to_index)

        # Construct the transaction
        tx_list = self.client.get_unspent_tx_output_list(
            from_monitor, from_index)
        outlays = [{'value': value, 'receiver': target_address}]
        tx_proposal = self.client.generate_tx(from_monitor, from_index,
                                              tx_list, outlays)

        # Submit the transaction
        response = self.client.submit_tx(tx_proposal)
        self.known_accounts[from_account["name"]][
            "sender_tx_receipt"] = response.sender_tx_receipt
        self.known_accounts[to_account["name"]][
            "recipient_tx_receipt_list"] = response.receiver_tx_receipt_list

        return 'Transaction submitted with key_images: {}'.format(
            response.sender_tx_receipt.key_image_list)

    @mob_command
    def status(self, account):
        """ Return the status of the most recent transaction for an account
        """
        transaction_status = {
            0: "Unknown",
            1: "Pending",
            2: "Verified",
            3: "TombstoneBlockExceeded",
        }

        if "sender_tx_receipt" in account:
            status = self.client.get_tx_status_as_sender(
                account["sender_tx_receipt"])
            return "Transaction status is: " + transaction_status[status]
        elif "recipient_tx_receipt_list" in account:
            ret = ""
            for i, receipt in enumerate(account["recipient_tx_receipt_list"]):
                status = self.client.get_tx_status_as_receiver(receipt)
                ret += "{}: {}\n".format(i, transaction_status[status])
            return ret
        else:
            return 'No transaction has been sent.'

    # FIXME: TODO
    @mob_command
    def create_withdrawal(self, value, from_account, from_index):
        """ Create and display a withdrawal QR code
        Usage: create-withdrawal <value> <from_account/#>
        """
        from_credentials = self.get_account_credentials(from_account)
        sender = self.client.get_sender(from_credentials, from_index)
        monitor_id = self.client.get_monitor_id(from_credentials, from_index)
        all_outputs = self.client.get_tx_output_list(monitor_id, from_index)
        spendable_outputs = self.client.get_spendable_outputs(
            sender, all_outputs)
        to_credentials = self.client.generate_entropy()
        receiver = self.client.get_receiver(to_credentials)
        sender_tx_receipt, receiver_tx_receipt = self.client.send_payment(
            sender, spendable_outputs, receiver, value)[0, 1]
        from_account["sender_tx_receipt"] = sender_tx_receipt
        del from_account["receiver_tx_receipt"]  # clear any old tx
        tx_public_key = receiver_tx_receipt.tx_public_key
        result = ('Transaction submitted with key_image: {}'.format(
            sender_tx_receipt.key_image))
        status = status(args[1])
        while (status == 0):
            time.sleep(1)
            status = status(args[1])
        assert (status == 1)
        b58_code = self.client.get_transfer_code(to_credentials, tx_public_key)
        result += _qrcode(b58code)
        result += ("Scan this code to complete your withdrawal.")

    # FIXME: TODO
    @mob_command
    def withdraw(self, b58code, to_account, to_index):
        """ Withdraw funds to a subaddress
        Usage: withdraw <b58code> <to_account> <to_index>
        """
        if not b58re.match(b58code):
            raise ClientError('invalid base58 code: "{}"'.format(b58code))
        from_credentials, tx_public_key, memo = self.client.read_transfer_code(
            b58_code)
        txo = self.client.get_tx_output(tx_public_key)
        value = txo.value
        sender = self.client.get_sender(from_credentials)
        to_credentials = self.get_account_credentials(to_account)
        receiver = self.client.get_receiver(to_credentials, to_index)
        receiver_tx_receipt = self.client.send_payment(sender, [txo], receiver,
                                                       value)[1]
        to_account["receiver_tx_receipt"] = receiver_tx_receipt
        del to_account["sender_tx_receipt"]  # clear any old tx
        result = ('Transaction submitted with tx_public_key: {}'.format(
            receiver_tx_receipt.tx_public_key))

    # FIXME: TODO
    @mob_command
    def create_deposit(self, value, to_account, to_index):
        """ create and display a deposit QR code
        Usage: create-deposit <value> <to_account> <to_index>
        """
        to_credentials = self.get_account_credentials(to_account)
        receiver = self.client.get_receiver(to_credentials, to_index)
        b58_code = self.client.get_request_code(receiver, value)
        result = _qrcode(b58code)
        result += ("Scan this code to complete your deposit.")

    # FIXME: TODO
    @mob_command
    def deposit(self, b58code, from_account, from_index):
        """ deposit funds from a subaddress
        Usage: deposit <b58code> <from_account/#>
        """
        if not b58re.match(b58code):
            raise ClientError('invalid base58 code: "{}"'.format(b58code))
        receiver, value, memo = self.client.read_request_code(b58_code)
        from_credentials = self.get_account_credentials(from_account)
        sender = self.client.get_sender(from_credentials, from_index)
        monitor_id = self.client.get_monitor_id(from_credentials, from_index)
        all_outputs = self.client.get_tx_output_list(monitor_id, from_index)
        spendable_outputs = self.client.get_spendable_outputs(
            sender, all_outputs)
        sender_tx_receipt = self.client.send_payment(sender, spendable_outputs,
                                                     receiver, value)[0]
        from_account["sender_tx_receipt"] = sender_tx_receipt
        del from_account["receiver_tx_receipt"]  # clear any old tx
        return 'Transaction submitted with key_image: {}'.format(
            sender_tx_receipt.key_image)

    # FIXME: TODO
    @mob_command
    def mobilecoind_test(self, delay_msec):
        """ Return the status of the most recent transaction
        Usage: test <msec>
        """
        start = self.client.get_ledger_info()
        time.sleep(0.001 * delay_msec)
        end = self.client.get_ledger_info()
        new_blocks = end[0] - start[0]
        new_txos = end[1] - start[1]
        if new_blocks > 0:
            result = (
                'downloaded {0:5d} new blocks     ( {1:5d} per second )\n'.
                format(new_blocks, new_blocks / (0.001 * delay_msec)))
            result += (
                'downloaded {0:5d} new txos       ( {1:5d} per second )\n'.
                format(new_txos, new_txos / (0.001 * delay_msec)))
            return result
        else:
            return 'No new blocks processed in {} milliseconds.'.format(
                delay_msec)

    def parse_index_range(self, index_range_string):
        """ Parse an index range of the form "[#,#]"
        """
        if index_range_string[0] != '[' or index_range_string[-1] != ']':
            raise ClientError('failed to parse index range from "{}"'.format(
                index_range_string))
        else:
            indices = []
            for index_string in index_range_string[1:-1].split(','):
                index = int(index_string)
                indices.append(index)
            return {"first_index": indices[0], "last_index": indices[1]}

    def get_account_credentials(self, account):
        """ Returns the credentials for an account
        """
        if "entropy" in account:
            return self.client.get_account_key(
                bytes.fromhex(account["entropy"]))
        else:
            raise ClientError('account "{}" is malformed'.format(
                account["name"]))


# TODO
# this regular expression matches valid base 58 strings
b58re = re.compile(
    r'[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*')


def get_qrcode(b58code):
    """ Add a QR code to the buffer
    """
    qr = qrcode.QRCode(border=0)
    qr.add_data(b58code)
    qr.make()
    #qr.print_ascii(out=buffer)
    result = '\n\nqrcode content: {}\n\n'.format(b58code)
    return result
