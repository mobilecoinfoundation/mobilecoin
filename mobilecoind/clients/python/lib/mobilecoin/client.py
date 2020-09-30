# Copyright (c) 2018-2020 MobileCoin Inc.

# Python wrappers for the gRPC service `MobilecoindAPI` organized as a `Client` object

import grpc

from google.protobuf import empty_pb2
from .external_pb2 import *
from .blockchain_pb2 import *
from .mobilecoind_api_pb2 import *
from .mobilecoind_api_pb2_grpc import *

import time, datetime
from typing import Tuple, Optional

MONITOR_SYNC_INTERVAL_SECONDS = 0.5
LEDGER_SYNC_INTERVAL_SECONDS = 0.5

DEFAULT_SUBADDRESS_INDEX = 0

# see transaction/core/src/constants.rs
MINIMUM_FEE = 0.010 * 1_000_000_000_000

# Transaction Status Codes
TX_STATUS_UNKNOWN = TxStatus.Unknown
TX_STATUS_VERIFIED = TxStatus.Verified
TX_STATUS_TOMBSTONE_BLOCK_EXCEEDED = TxStatus.TombstoneBlockExceeded
TX_STATUS_INVALID_CONFIRMATION_NUMBER = TxStatus.InvalidConfirmationNumber

class MonitorNotFound(Exception):
    """ When a Monitor is not Found"""
    pass


class Client(object):
    """ Manages the MobileCoin Wallet Client.
    """
    def __init__(self, daemon, ssl):
        """ Initializes the client and connects to a mobilecoind service.
          daemon -- address and port of mobilecoind daemon
          ssl    -- use SSL to connect
        """

        if ssl:
            credentials = grpc.ssl_channel_credentials()
            self.channel = grpc.secure_channel(daemon, credentials)
        else:
            self.channel = grpc.insecure_channel(daemon)
        self.stub = MobilecoindAPIStub(self.channel)

    def __del__(self):
        """ Close the gRPC connection upon deletion."""
        try:
            self.channel.close()
        except Exception:
            pass

    def add_monitor(self,
                    account_key: bytes,
                    first_subaddress: int = DEFAULT_SUBADDRESS_INDEX,
                    num_subaddresses: int = 1,
                    first_block: int = 0):
        """ Create a process that watches the ledger for tx outputs belonging to a
        set of subaddresses, each specified by account_key and an index.
        """
        request = AddMonitorRequest(account_key=account_key,
                                    first_subaddress=first_subaddress,
                                    num_subaddresses=num_subaddresses,
                                    first_block=first_block)
        return self.stub.AddMonitor(request).monitor_id

    def remove_monitor(self, monitor_id: bytes):
        """ Remove an existing monitor and delete any data it has stored.
        """
        request = RemoveMonitorRequest(monitor_id=monitor_id)
        return self.stub.RemoveMonitor(request)

    def get_monitor_list(self):
        """ Returns a list of all active monitors.
        """
        return self.stub.GetMonitorList(empty_pb2.Empty()).monitor_id_list

    def get_monitor_status(self, monitor_id: bytes):
        """ Returns a status report for a monitor process.
        """
        request = GetMonitorStatusRequest(monitor_id=monitor_id)
        response = self.stub.GetMonitorStatus(request)
        return response.status

    def get_unspent_tx_output_list(self,
                                   monitor_id: bytes,
                                   subaddress_index: int = DEFAULT_SUBADDRESS_INDEX):
        """ Returns the list of tx outputs collected for a subaddress.
        """
        request = GetUnspentTxOutListRequest(monitor_id=monitor_id,
                                             subaddress_index=subaddress_index)
        response = self.stub.GetUnspentTxOutList(request)
        return response.output_list

    def get_balance(self,
                    monitor_id: bytes,
                    subaddress_index: int = DEFAULT_SUBADDRESS_INDEX):
        """ Returns the sum of unspent tx outputs collected for a subaddress.
        """
        uoutput_list = self.get_unspent_tx_output_list(monitor_id, subaddress_index)
        balance = 0
        for utxo in uoutput_list:
            balance += utxo.value
        return balance

    def get_monitor_id(self,
                       account_key: bytes,
                       subaddress_index: int = DEFAULT_SUBADDRESS_INDEX):
        """ Returns the monitor for a given subaddress, if one exists.
        """
        monitor_id_list = self.get_monitor_list()
        target_vpk = account_key.view_private_key
        target_spk = account_key.spend_private_key

        best_monitor_id = b''
        best_next_block = 0
        for monitor_id in monitor_id_list:
            status = self.get_monitor_status(monitor_id)
            if target_vpk == status.account_key.view_private_key and target_spk == status.account_key.spend_private_key:
                if subaddress_index >= status.first_subaddress and subaddress_index <= status.first_subaddress + status.num_subaddresses:
                    if status.next_block >= best_next_block:
                        best_next_block = status.next_block
                        best_monitor_id = monitor_id
        if best_monitor_id:
            return best_monitor_id
        else:
            raise MonitorNotFound

    #
    # Utilities
    #

    def generate_entropy(self):
        """ Generate 32 bytes of entropy using a cryptographically secure RNG.
        """
        return self.stub.GenerateEntropy(empty_pb2.Empty()).entropy

    def get_account_key(self, entropy: bytes):
        """ Get the private keys from entropy.
        """
        request = GetAccountKeyRequest(entropy=entropy)
        return self.stub.GetAccountKey(request).account_key

    def get_public_address(self,
                           monitor_id: bytes,
                           subaddress_index: int = DEFAULT_SUBADDRESS_INDEX):
        """ Returns the public address for a given monitor and index
        """
        request = GetPublicAddressRequest(
            monitor_id=monitor_id, subaddress_index=subaddress_index)
        return self.stub.GetPublicAddress(request)

    def parse_address_code(self,
                           b58_code: str):
        """ Parse a b58 encoded public address
        """
        request = ParseAddressCodeRequest(b58_code=b58_code)
        response = self.stub.ParseAddressCode(request)
        return response.receiver

    def create_address_code(self, receiver):
        """ Create a b58 encoding for a public address
        """
        request = CreateAddressCodeRequest(receiver=receiver)
        return self.stub.CreateAddressCode(request).b58_code

    def parse_request_code(self, b58_code: str):
        """ Parse a b58 request code to recover content.
        """
        request = ParseRequestCodeRequest(b58_code=b58_code)
        response = self.stub.ParseRequestCode(request)
        return response.receiver, response.value, response.memo

    def create_request_code(self, receiver, value: int = 0, memo: str = ""):
        """ Create a "request code" used to generate a QR code for wallet apps.
        """
        request = CreateRequestCodeRequest(receiver=receiver,
                                           value=value,
                                           memo=memo)
        return self.stub.CreateRequestCode(request).b58_code

    def parse_transfer_code(self, b58_code: str):
        """ Parse a b58 transfer code to recover content.
        """
        request = ParseTransferCodeRequest(b58_code=b58_code)
        response = self.stub.ParseTransferCode(request)
        return response

    def crate_transfer_code(self, entropy: bytes, tx_public_key, memo: str = ""):
        """ Create a "transfer code" used to generate a QR code for wallet apps.
        """
        request = CreateTransferCodeRequest(entropy=entropy,
                                            tx_public_key=tx_public_key,
                                            memo=memo)
        return self.stub.CreateTransferCode(request).b58_code

    #
    # Transactions
    #

    def generate_tx(self,
                    sender_monitor_id: bytes,
                    change_subaddress: int,
                    input_list,
                    outlay_dict,
                    fee: int = 0,
                    tombstone: int = 0):
        """ Prepares a transaction. If the fee is zero, we use the default minimum fee. Mix-ins and other
        complexities of the MobileCoin protocol are handled automatically.
        """
        outlay_list = [
            Outlay(value=r['value'], receiver=r['receiver'])
            for r in outlay_dict
        ]
        request = GenerateTxRequest(sender_monitor_id=sender_monitor_id,
                                    change_subaddress=change_subaddress,
                                    input_list=input_list,
                                    outlay_list=outlay_list,
                                    fee=fee,
                                    tombstone=tombstone)
        return self.stub.GenerateTx(request).tx_proposal

    def generate_optimization_tx(self,
                                 monitor_id: bytes,
                                 subaddress: int = DEFAULT_SUBADDRESS_INDEX):
        """ Due to limits on the number of inputs allowed for a transaction, a wallet can contain
        more value than is spendable in a single transaction. This generates a self-payment
        that combines small value tx outputs together.
        """
        request = GenerateOptimizationTxRequest(monitor_id=monitor_id,
                                                subaddress=subaddress)
        return self.stub.GenerateOptimizationTx(request).tx_proposal

    def generate_transfer_code_tx(self,
                                  sender_monitor_id: bytes,
                                  change_subaddress: int,
                                  input_list,
                                  value: int,
                                  fee: int,
                                  tombstone: int,
                                  memo: str):
        """ Prepares a transaction that can be submitted to fund a transfer code for a new
        one time account.
        """
        request = GenerateTransferCodeTxRequest(
            sender_monitor_id=sender_monitor_id,
            change_subaddress=change_subaddress,
            input_list=input_list,
            value=value,
            fee=fee,
            tombstone=tombstone,
            memo=memo)
        response = self.stub.GenerateTransferCodeTx(request)
        return response.tx_proposal, response.entropy

    def generate_tx_from_tx_out_list(self,
                                     account_key: bytes,
                                     input_list,
                                     receiver,
                                     fee: int):
        request = GenerateTxFromTxOutListRequest(
            account_key=account_key,
            input_list=input_list,
            receiver=receiver,
            fee=fee,
        )
        response = self.stub.GenerateTxFromTxOutList(request)
        return response.tx_proposal

    def submit_tx(self, tx_proposal):
        """ Submit a prepared transaction, optionall requesting a tombstone block.
        """
        request = SubmitTxRequest(tx_proposal=tx_proposal)
        response = self.stub.SubmitTx(request)
        return response

    #
    # Databases
    #

    def get_ledger_info(self):
        """ Returns a status report for mobilecoind's ledger maintenance.
        """
        info = self.stub.GetLedgerInfo(empty_pb2.Empty())
        return info.block_count, info.txo_count

    def get_block_info(self, block: int):
        """ Returns a status report for a ledger block.
        """
        request = GetBlockInfoRequest(block=block)
        info = self.stub.GetBlockInfo(request)
        return info.key_image_count, info.txo_count

    def get_block(self, block: int):
        """ Returns detailed information for a ledger block.
        """
        request = GetBlockRequest(block=block)
        block_contents = self.stub.GetBlock(request)
        return block_contents

    def get_tx_status_as_sender(self, sender_tx_receipt):
        """ Check if a key image appears in the ledger.
        """
        request = GetTxStatusAsSenderRequest(receipt=sender_tx_receipt)
        response = self.stub.GetTxStatusAsSender(request)
        return response.status

    def get_tx_status_as_receiver(self, receiver_tx_receipt):
        """ Check if a transaction public key appears in the ledger.
        """
        request = GetTxStatusAsReceiverRequest(receipt=receiver_tx_receipt)
        response = self.stub.GetTxStatusAsReceiver(request)
        return response.status

    #
    # Blockchain and network info
    #

    def get_network_status(self):
        """ Returns the total network height and our current sync height
        """
        response = self.stub.GetNetworkStatus(empty_pb2.Empty())
        return (response.network_highest_block_index,
                response.local_block_index,
                response.is_behind)

    #
    # Convenience functions using the mobilecoind API
    #

    def wait_for_ledger(self,
                        max_blocks_to_sync: int = 100,
                        timeout_seconds: int = 10) -> Tuple[bool, int, int, Optional[float]]:
        """ Check if the local copy of the ledger is in sync

        If we are behind, wait until the ledger downloads up to max_blocks_to_sync
        If we are still behind, return (True, local blocks, remote blocks, rate in blocks/sec)
        If we are in sync, return (False, local blocks, remote blocks, None)

        """
        remote_count, local_count, is_behind = self.get_network_status()

        if not is_behind:
            return (is_behind, local_count, remote_count, None)

        start = datetime.datetime.now()
        initial_local_count = local_count
        while is_behind:
            time.sleep(LEDGER_SYNC_INTERVAL_SECONDS)

            remote_count, local_count, is_behind = self.get_network_status()

            delta = datetime.datetime.now() - start
            total_blocks_synced = local_count - initial_local_count

            if total_blocks_synced > max_blocks_to_sync:
                break

            if delta.total_seconds() > timeout_seconds:
                break

        blocks_per_second = total_blocks_synced / delta.total_seconds()
        return (is_behind, local_count, remote_count, blocks_per_second)

    def wait_for_monitor(self,
                         monitor_id: bytes,
                         max_blocks_to_sync: int = 100,
                         timeout_seconds: int = 10) -> Tuple[bool, int, int, Optional[float]]:
        """ Check if a monitor is in sync

        If we are behind, wait until the monitor processes up to max_blocks_to_sync
        If we are still behind, return (True, monitor next block, remote blocks, rate in blocks/sec)
        If we are in sync, return (False, monitor next block, remote blocks, None)

        """

        # check the ledger and monitor
        remote_count, local_count, ledger_is_behind = self.get_network_status()
        next_block = self.get_monitor_status(monitor_id).next_block
        monitor_is_behind = ledger_is_behind or (next_block < local_count)

        if not monitor_is_behind:
            return (monitor_is_behind, next_block, remote_count, None)

        start = datetime.datetime.now()
        initial_next_block = next_block
        while monitor_is_behind:
            time.sleep(MONITOR_SYNC_INTERVAL_SECONDS)

            remote_count, local_count, ledger_is_behind = self.get_network_status()
            next_block = self.get_monitor_status(monitor_id).next_block
            monitor_is_behind = ledger_is_behind or (next_block < local_count)

            delta = datetime.datetime.now() - start
            total_blocks_synced = next_block - initial_next_block

            if total_blocks_synced > max_blocks_to_sync:
                break

            if delta.total_seconds() > timeout_seconds:
                break

        blocks_per_second = total_blocks_synced / delta.total_seconds()
        return (monitor_is_behind, next_block, remote_count, blocks_per_second)
