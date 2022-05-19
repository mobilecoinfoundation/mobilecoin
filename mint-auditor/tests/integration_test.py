#!/usr/bin/env python3

# Copyright (c) 2022 The MobileCoin Foundation
#
# Integration test that tests the mint auditor tracks mints and burns.

import argparse
import grpc
import logging
import subprocess
import sys
import time
from google.protobuf import empty_pb2
from mint_auditor_pb2 import *
from mint_auditor_pb2_grpc import *
from mobilecoind_api_pb2 import *
from mobilecoind_api_pb2_grpc import *


logging.basicConfig(stream = sys.stdout, level = logging.INFO, format="%(levelname)s:%(module)s:%(lineno)s: %(message)s")


class MintAuditorClient:
    def __init__(self, address, ssl=False):
        if ssl:
            credentials = grpc.ssl_channel_credentials()
            self.channel = grpc.secure_channel(address, credentials)
        else:
            self.channel = grpc.insecure_channel(address)
        self.stub = MintAuditorApiStub(self.channel)

    def get_last_block_audit_data(self):
        return self.stub.GetLastBlockAuditData(empty_pb2.Empty())

    def get_counters(self):
        return self.stub.GetCounters(empty_pb2.Empty())


class MobilecoindClient:
    def __init__(self, address, ssl=False):
        if ssl:
            credentials = grpc.ssl_channel_credentials()
            self.channel = grpc.secure_channel(address, credentials)
        else:
            self.channel = grpc.insecure_channel(address)
        self.stub = MobilecoindAPIStub(self.channel)

    def new_random_monitor(self):
        """Create a new monitor from a random mnemomic"""
        new_menmonic = self.stub.GenerateMnemonic(empty_pb2.Empty()).mnemonic
        account_key = self.stub.GetAccountKeyFromMnemonic(
            GetAccountKeyFromMnemonicRequest(mnemonic=new_menmonic)
        ).account_key
        monitor_id = self.stub.AddMonitor(
            AddMonitorRequest(
                account_key=account_key,
                num_subaddresses=1,
            )
        ).monitor_id
        return monitor_id

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


class MintAuditorTest:
    def __init__(self, args):
        self.args = args
        self.mobilecoind_client = MobilecoindClient(args.mobilecoind_addr)
        self.mint_auditor_client = MintAuditorClient(args.mint_auditor_addr)

    def run(self):
        monitor_id = self.mobilecoind_client.new_random_monitor()

        try:
            b58_addr = self.mobilecoind_client.get_b58_public_address(monitor_id)
            logging.info(f"Minting to {b58_addr}")
            token_id = 1
            mint_amount = 10000

            # Get the network block height and wait for the mint auditor to catch up
            response = self.wait_for_mint_auditor_to_sync()
            previous_minted_amount = dict(response.block_audit_data.balance_map).get(token_id) or 0

            # Mint tokens that go into the new wallet we generated
            logging.info(f"Minting {mint_amount} tokens of token_id {token_id}")
            output = subprocess.check_output(" ".join([
                self.args.mint_client_bin,
                "generate-and-submit-mint-tx",
                f"--node {self.args.node_url}",
                f"--signing-key {self.args.mint_signing_key}",
                f"--recipient {b58_addr}",
                f"--token-id {token_id}",
                f"--amount {mint_amount}",
            ]), shell=True)
            logging.info(f"Mint client output: {output}")

            # Give the network time to process the mint and then for mobilecoind and the mint auditor to catch up
            self.wait_for_balance(monitor_id, token_id, mint_amount)

            response = self.wait_for_mint_auditor_to_sync()

            current_minted_amount = dict(response.block_audit_data.balance_map).get(token_id)
            assert current_minted_amount == previous_minted_amount + mint_amount, (current_minted_amount, previous_minted_amount, mint_amount)

            # Burn 300 tokens
            burn_amount = 300
            fee_amount = 1024
            utxos = self.mobilecoind_client.get_utxos(monitor_id, token_id)
            tx_proposal = self.mobilecoind_client.generate_burn_redemption_tx(
                monitor_id,
                utxos,
                burn_amount,
                fee_amount,
                token_id,
            )
            logging.info("Submitting burn transaction")
            submit_response = self.mobilecoind_client.submit_tx(tx_proposal)

            # Wait for the transaction to go through
            logging.info("Verifying burn transaction")
            expected_balance = mint_amount - burn_amount - fee_amount
            self.wait_for_balance(monitor_id, token_id, expected_balance)

            response = self.wait_for_mint_auditor_to_sync()

            previous_minted_amount = current_minted_amount
            current_minted_amount = dict(response.block_audit_data.balance_map).get(token_id)
            assert current_minted_amount == previous_minted_amount - burn_amount, (current_minted_amount, previous_minted_amount, burn_amount)

            # Sanity check the counters
            logging.info("Checking counters")
            counters = self.mint_auditor_client.get_counters()
            assert counters.num_blocks_synced == response.block_index + 1, (counters.num_blocks_synced, response.block_index)
            assert counters.num_burns_exceeding_balance == 0, counters.num_burns_exceeding_balance
            assert counters.num_mint_txs_without_matching_mint_config == 0, counters.num_mint_txs_without_matching_mint_config

            logging.info("All tests passed")

        finally:
            self.mobilecoind_client.remove_monitor(monitor_id)

    def wait_for_balance(self, monitor_id, token_id, expected_balance):
        """Poll mobilecoind until it has the expected balance"""

        for _ in range(20):
            self.mobilecoind_client.wait_for_monitor_to_sync(monitor_id)

            # Balance should show up in mobilecoild
            balance = self.mobilecoind_client.get_balance(monitor_id, token_id)
            if balance == expected_balance:
                break

            time.sleep(1)

        assert balance == expected_balance, (balance, expected_balance)



    def wait_for_mint_auditor_to_sync(self):
        """Wait for the mint auditor to sync to the network block height.
        Return the last block audit data"""
        network_block_index = self.mobilecoind_client.get_network_block_index()
        for _ in range(20):
            response = self.mint_auditor_client.get_last_block_audit_data()
            if response.block_index == network_block_index:
                break

            time.sleep(1)

        assert response.block_index == network_block_index, f'block index mismatch: {response.block_index} != {network_block_index}'
        logging.info(f"Last block audit data: {response}")
        return response


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--mobilecoind-addr",
                        type=str,
                        help="mobilecoind host:port")
    parser.add_argument("--mint-auditor-addr",
                        type=str,
                        help="mint auditor host:port")
    parser.add_argument("--mint-client-bin",
                        type=str,
                        help="path to the mc-consensus-mint-client binary")
    parser.add_argument("--node-url",
                        type=str,
                        help="node to issue a mint transaction to")
    parser.add_argument("--mint-signing-key",
                        type=str,
                        help="path to the mint signing private key file")

    args = parser.parse_args()
    MintAuditorTest(args).run()
