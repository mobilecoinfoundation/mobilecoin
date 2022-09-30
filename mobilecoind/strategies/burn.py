#!/usr/bin/env python3

# Copyright (c) 2018-2022 The MobileCoin Foundation

"""
The purpose of this strategy is to burn a specified amount of funds from some account.

This can be used in tests and demos of the reserve-auditor work flow.



Example setup and usage:
```
    python3 burn.py --key ../../../target/sample_data/keys/account5.json --token-id 1 --value 1000000 --fee 2000
```
"""
import argparse
import glob
import grpc
import json
import logging
import os
import sys
import time
from google.protobuf import empty_pb2
from mobilecoind_api_pb2 import *
from mobilecoind_api_pb2_grpc import *

logging.basicConfig(stream = sys.stdout, level = logging.INFO, format="%(levelname)s:%(module)s:%(lineno)s: %(message)s")


def parse_args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mobilecoind-host",
                        default="localhost",
                        type=str,
                        help="Mobilecoind host")
    parser.add_argument("--mobilecoind-port",
                        default="4444",
                        type=str,
                        help="Mobilecoind port")
    parser.add_argument("--key",
                        type=str,
                        help="Path a private account key json, in the sample_data format")
    parser.add_argument("--max-seconds",
                        type=int,
                        default=40,
                        help="Number of seconds to wait for a tx to clear")
    parser.add_argument("--token-id",
                        type=int,
                        help="Token id to burn")
    parser.add_argument("--value",
                        type=int,
                        default=0,
                        help="Quantity of this token id to burn")
    parser.add_argument("--fee",
                        type=int,
                        default=20,
                        help="Amount of this token id to use as a fee")
    parse.add_argument("--burn-redemption-memo",
                        type=str
                        help="Burn redemption memo to use. This utf8 string will be padded up to 64 bytes with null characters. Typically it would be expected to be an ethereum address e.g. 0xaaaaa...")

    return parser.parse_args()

class MobilecoindClient:
    def __init__(self, address, ssl=False):
        if ssl:
            credentials = grpc.ssl_channel_credentials()
            self.channel = grpc.secure_channel(address, credentials)
        else:
            self.channel = grpc.insecure_channel(address)
        self.stub = MobilecoindAPIStub(self.channel)

    def new_monitor_from_keyfile(self, file):
        """Create a new monitor from a key file, returns AccountData"""

        # Load the account key from file
        with open(file, 'r') as f:
            key_data = json.load(f)

        # Remove discovery fqdn, as this causes InvalidTxOutMembershipProof
        key_data['acct_fqdn'] = None

        # Generate an account key from this root entropy
        if 'mnemonic' in key_data:
            resp = self.stub.GetAccountKeyFromMnemonic(
                GetAccountKeyFromMnemonicRequest(
                    mnemonic=key_data['mnemonic']))
        elif 'root_entropy' in key_data:
            resp = self.stub.GetAccountKeyFromRootEntropy(
                GetAccountKeyFromRootEntropyRequest(
                    root_entropy=bytes(key_data['root_entropy'])))
        else:
            raise Exception('unknown key format')

        account_key = resp.account_key

        # Add this account to the wallet
        resp = self.stub.AddMonitor(
            AddMonitorRequest(account_key=account_key, first_subaddress=0, num_subaddresses=1))
        return resp.monitor_id

    def remove_monitor(self, monitor_id):
        self.stub.RemoveMonitor(RemoveMonitorRequest(monitor_id=monitor_id))

    def get_b58_public_address(self, monitor_id):
        return self.stub.GetPublicAddress(
            GetPublicAddressRequest(monitor_id=monitor_id)
        ).b58_code

    def get_balance(self, monitor_id, token_id, subaddress_index=0):
        return self.stub.GetBalance(
            GetBalanceRequest(
                monitor_id=monitor_id,
                subaddress_index=subaddress_index,
                token_id=token_id,
            )
        ).balance

    def get_network_block_index(self):
        return self.stub.GetNetworkStatus(
            empty_pb2.Empty()
        ).network_highest_block_index

    def get_utxos(self, monitor_id, token_id, subaddress_index=0):
        return self.stub.GetUnspentTxOutList(
            GetUnspentTxOutListRequest(
                monitor_id=monitor_id,
                subaddress_index=subaddress_index,
                token_id=token_id,
            )
        ).output_list

    def generate_burn_redemption_tx(
        self,
        monitor_id,
        input_list,
        burn_amount,
        fee,
        token_id,
        change_subaddress=0,
        tombstone=None,
        redemption_memo=None,
        enable_destination_memo=False,
    ):
        if tombstone is None:
            tombstone = self.get_network_block_index() + 10

        request = GenerateBurnRedemptionTxRequest(
            sender_monitor_id=monitor_id,
            change_subaddress=change_subaddress,
            input_list=input_list,
            burn_amount=burn_amount,
            fee=fee,
            tombstone=tombstone,
            token_id=token_id,
            redemption_memo=redemption_memo,
            enable_destination_memo=enable_destination_memo,
        )
        return self.stub.GenerateBurnRedemptionTx(request).tx_proposal

    def submit_tx(self, tx_proposal):
        return self.stub.SubmitTx(
            SubmitTxRequest(
                tx_proposal=tx_proposal,
            )
        )

    def wait_for_monitor_to_sync(self, monitor_id, poll_interval=0.1):
        while True:
            network_block_index = self.get_network_block_index()
            status = self.stub.GetMonitorStatus(
                GetMonitorStatusRequest(
                    monitor_id=monitor_id
                )
            ).status
            if status.next_block >= network_block_index:
                break
            time.sleep(poll_interval)


if __name__ == '__main__':
    args = parse_args()
    logging.debug(args)

    # The memo bytes are expected to be exactly 64 in length.
    # We are just utf-8 encoding whatever the user gives us and padding it up,
    # mobilecoind returns an error if this is too long.
    memo_bytes = args.burn_redemption_memo.encode("utf-8").ljust(64, '\0')

    client = MobilecoindClient(f"{args.mobilecoind_host}:{args.mobilecoind_port}")
    monitor = client.new_monitor_from_keyfile(args.key)

    client.wait_for_monitor_to_sync(monitor)

    balance = client.get_balance(monitor, args.token_id)

    if balance < args.value + args.fee:
        raise Exception(f"Insufficient balance: {balance} < {args.value} + {args.fee}")

    utxos = client.get_utxos(monitor, args.token_id)
    tx_proposal = client.generate_burn_redemption_tx(
        monitor_id = monitor,
        input_list = utxos,
        burn_amount = args.value,
        fee = args.fee,
        token_id = args.token_id,
        redemption_memo = memo_bytes,
    )
    logging.info("Constructed burn transaction")
    logging.debug(tx_proposal)

    # Search for the burn txout. mobilecoind will create one "outlay" which is
    # the burn, and there is a map in the TxProposal that tells you which TxOut it is.
    if len(tx_proposal.outlay_index_to_tx_out_index) != 1:
        logging.warning(f"Unexpected number of outlays: {tx_proposal.outlay_index_to_tx_out_index}")
        raise Exception("Couldn't determine burn output")
    tx_out_public_key_bytes = tx_proposal.tx.prefix.outputs[tx_proposal.outlay_index_to_tx_out_index[0]].public_key.data
    tx_out_public_key_hex = tx_out_public_key_bytes.hex()
    logging.info(f"*** The hex bytes of burn TxOut public key are: {tx_out_public_key_hex}")

    logging.info("Submitting burn transaction")
    submit_response = client.submit_tx(tx_proposal)
    print(submit_response)

    time.sleep(3)

    client.wait_for_monitor_to_sync(monitor)
    new_balance = client.get_balance(monitor, args.token_id)

    if new_balance == balance - args.value - args.fee:
        logging.info("Burn transaction was successful")
    else:
        logging.error("Burn transaction appears to be unsuccessful")
        sys.exit(1)
