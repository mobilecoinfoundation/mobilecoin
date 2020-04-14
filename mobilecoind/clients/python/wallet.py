# Copyright (c) 2018-2020 MobileCoin Inc.

# WIP: Implementing QR code flow for exchanges

import qrcode
import sys
import os.path
import traceback
import json
import time
import re
import grpc

import cmd

from mob_client import mob_client, MonitorNotFound


def mob_command(func):
    """ Decorator to handle possible errors
    """
    def wrapper(session, *args, **kwargs):
        try:
            if args and args[0] == '':
                success_str = func(session)
            else:
                success_str = func(session, *args, **kwargs)
            print(success_str)
        except ClientError as e:
            print(f"Client error:\n{type(e).__name__}:{e.args}")
        except grpc.RpcError as e:
            print(
                f"mobilecoind error:\n{type(e).__name__}:{e.args}\n{traceback.format_exc()}"
            )
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
        """quit - quit the program"""
        sys.exit(0)

    def do_load(self, args):
        """load (optional)<file: defaults to accounts.json> - loads a table of known accounts from a json file"""
        self.load_accounts(args)

    def do_new_account(self, _args):
        """new_account - Create a new account"""
        self.new_account()

    def do_accounts(self, _args):
        """list-accounts - list known accounts"""
        self.list_accounts()

    def do_monitor(self, args):
        """monitor <account> (optional)<[min,max]: defaults to [0,10000]> - Monitor txos for a set of subaddresses"""
        parts = args.split()
        if len(parts) == 0:
            print(
                "Please provide one account to monitor and optionally a subaddress range."
            )
        if len(self.known_accounts) == 0:
            print("You have not yet loaded any accounts to monitor.")
            return
        if len(parts) > 2:
            print(
                "Please provide one account to monitor and optionally a subaddress range."
            )
            return
        account = self.known_accounts[parts[0]]
        index_range = None
        if len(parts) == 2:
            index_range = self.parse_index_range(parts[1])
        self.add_monitor(account, index_range)

    def do_monitors(self, _args):
        """monitors - list active monitors"""
        self.list_monitors()

    def do_public_address(self, args):
        """public-address <account> (optional)<index: defaults to 0> - print public address for account"""
        parts = args.split()
        if len(self.known_accounts) == 0:
            print("You have not loaded any accounts to monitor.")
            return
        if len(parts) == 0:
            print("Please provide one monitored account and optional index.")
            return
        if len(parts) > 2:
            print(
                "Please provide one monitored account and the subaddress index for which to retrieve the public address."
            )
            return
        index = int(parts[1]) if len(parts) > 1 else 0
        account = self.known_accounts[parts[0]]
        index = int(parts[1])
        self.get_public_address(account, index)

    def do_balance(self, args):
        """balance <account> (optional)<index: defaults to 0> - get the balance for a subaddress.
        """
        parts = args.split()
        if len(parts) == 0:
            print("Please provide one monitored account and optional index.")
            return
        if len(parts) > 2:
            print("Please provide account and optional index.")
            return
        index = int(parts[1]) if len(parts) > 1 else 0
        if parts[0] not in self.known_accounts:
            print("We are not tracking that account.")
            return
        self.check_balance(self.known_accounts[parts[0]], index)

    def do_transfer(self, args):
        """transfer <value> <from_account> <subaddress> <public_address>
            - Transfer funds from your account+subaddresses to a public address."""
        parts = args.split()
        if len(parts) != 4:
            print("Please provide all arguments")
            return
        parts = args.split()
        self.transfer(int(parts[0]), self.known_accounts[parts[1]], int(parts[2]), parts[3])

    def do_private_transfer(self, args):
        """private_transfer <value> <from_account> <subaddress> <to_account> <subaddress>
            - Transfer funds between accounts and subaddresses that you own."""
        if args.len() != 5:
            print("Please provide all arguments")
            return
        parts = args.split()
        self.private_transfer(int(parts[0]), self.known_accounts[parts[1]],
                              int(parts[2]), self.known_accounts[parts[3]],
                              int(parts[4]))

    def do_status(self, args):
        """status <account> - Print the status of the last transfer for a monitored account.
            Note: The status for transfers to an address not in known accounts will
                  remain pending.
        """
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
        return f"Loaded {len(self.known_accounts)} accounts."

    @mob_command
    def new_account(self):
        """ Create a new account.
        """
        # TODO
        pass

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
                    str += f'#{account_key} : account "{account_data["name"]}" '
                    str += f'is monitoring subaddress range [{status.first_block},{status.next_block}]\n'
            else:
                str += f'#{account_key} : account "{account_data["name"]}" is known, but has no monitors.\n'
        str = str[0:-1]  # remove the final '\n'
        return str

    @mob_command
    def add_monitor(self, account, index_range=None):
        """ Monitor incoming transactions for a set of subaddresses for a known alias.
        """
        print(f"Adding monitor for {account['name']}, scanning ledger for txos.")
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
        str = f'account "{account["name"]}" '
        str += f'added a monitor for subaddress range [{status.first_subaddress},{status.num_subaddresses}]'
        return str

    @mob_command
    def list_monitors(self):
        """ List active monitors.
        """
        # FIXME: Rebuild active monitors from mobilecoind session
        monitor_id_list = self.client.get_monitor_list()
        result = ('Account Monitor List:\n')
        for (i, id) in enumerate(monitor_id_list):
            status = self.client.get_monitor_status(id)
            result += f'#{i} [{id.hex()}]: account {id} is monitoring subaddress range [{status.first_block},{status.next_block}]'
        return result

    @mob_command
    def get_public_address(self, account, index):
        try:
            monitor_id = self.client.get_monitor_id(
                self.client.get_account_key(bytes.fromhex(account["entropy"])),
                index=index)
            public_address = self.client.get_public_address(monitor_id, index)
            # Note: We do not return the public address. All public addresses
            # in MobileCoin are wrapped in payment requests.
            request_code = self.client.get_request_code(public_address)
            return request_code
        except MonitorNotFound:
            return f"No monitors for account {account['name']}"

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
            subaddress_str = f'{account["name"]}/{index}'
            return '{} has {} pMOB @ block {} of {} available'.format(
                account["name"], balance, monitor_last_block, block_count)
        else:
            raise ClientError('no ledger blocks have been downloaded')

    @mob_command
    def transfer(self, value, from_account, from_index, to_public_address):
        """ Send funds to a public address.
        """
        # Get sender info and monitor
        from_credentials = self.get_account_credentials(from_account)
        from_monitor = self.client.get_monitor_id(from_credentials, from_index)

        # Decode b58 transfer code. Note: value and memo are irrelevant
        target_address, _value, _memo = self.client.read_request_code(to_public_address)

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

        return f'Transaction submitted with key_images: {response.sender_tx_receipt.key_image_list}'

    @mob_command
    def private_transfer(self, value, from_account, from_index, to_account, to_index):
        """ Send funds between accounts that are both owned by this wallet.
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

        return f'Transaction submitted with key_images: {response.sender_tx_receipt.key_image_list}'

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
                ret += f"{i}: {transaction_status[status]}\n"
            return ret
        else:
            return 'No transaction has been sent.'

    def parse_index_range(self, index_range_string):
        """ Parse an index range of the form "[#,#]"
        """
        if index_range_string[0] != '[' or index_range_string[-1] != ']':
            raise ClientError(f'failed to parse index range from "{index_range_string}"')
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
            raise ClientError(f'account "{account["name"]}" is malformed')
