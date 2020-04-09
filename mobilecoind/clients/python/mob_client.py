# Copyright (c) 2018-2020 MobileCoin Inc.

import external_pb2
from google.protobuf import empty_pb2
import grpc
import mobilecoind_api_pb2 as api
import mobilecoind_api_pb2_grpc as api_grpc

from random import randint


class mob_client:

    """ Initializes the client and connects to a mobilecoind service.
          daemon -- address and port of mobilecoind daemon
          ssl    -- use SSL to connect"""

    def __init__(self, daemon, ssl):
        if ssl:
            credentials = grpc.ssl_channel_credentials()
            self.channel = grpc.secure_channel(daemon, credentials)
        else:
            self.channel = grpc.insecure_channel(daemon)
        self.stub = api_grpc.MobilecoindAPIStub(self.channel)

    """ Close the gRPC connection upon deletion."""

    def __del__(self):
        try:
            self.channel.close()
        except Exception:
            pass

    #
    # Monitors
    #

    """ Create a process that watches the ledger for tx outputs belonging to a
        set of subaddresses, each specified by account_key and an index."""

    def add_monitor(self, account_key, first_subaddress=0, num_subaddresses=100000, first_block=0):
        request = api.AddMonitorRequest(
            account_key=account_key,
            first_subaddress=first_subaddress,
            num_subaddresses=num_subaddresses,
            first_block=first_block)
        return self.stub.AddMonitor(request).monitor_id

    """ Remove an existing monitor and delete any data it has stored.
    """

    def remove_monitor(self, monitor_id):
        request = api.RemoveMonitorRequest(monitor_id)
        return self.stub.RemoveMonitor(request)

    """ Returns a list of all active monitors.
    """

    def get_monitor_list(self):
        return self.stub.GetMonitorList(empty_pb2.Empty()).monitor_id_list

    """ Returns a status report for a monitor process.
    """

    def get_monitor_status(self, monitor_id):
        request = api.GetMonitorStatusRequest(monitor_id=monitor_id)
        response = self.stub.GetMonitorStatus(request)
        return response.status

    """ Returns the list of tx outputs collected for a subaddress.
    """

    def get_unspent_tx_output_list(self, monitor_id, index=0):
        request = api.GetUnspentTxOutListRequest(
            monitor_id=monitor_id,
            subaddress_index=index)
        response = self.stub.GetUnspentTxOutList(request)
        return response.output_list

    """ Returns the sum of unspent tx outputs collected for a subaddress.
    """

    def get_balance(self, monitor_id, index=0):
        uoutput_list = self.get_unspent_tx_output_list(monitor_id, index)
        balance = 0
        for utxo in uoutput_list:
            balance += utxo.value
        return balance

    """ Returns the monitor for a given subaddress, if one exists.
    """

    def get_monitor_id(self, account_key, index=0):
        monitor_id_list = self.get_monitor_list()
        target_vpk = account_key.view_private_key
        target_spk = account_key.spend_private_key

        best_monitor_id = b''
        best_next_block = 0
        for monitor_id in monitor_id_list:
            status = self.get_monitor_status(monitor_id)
            if target_vpk == status.account_key.view_private_key and target_spk == status.account_key.spend_private_key:
                if index >= status.first_subaddress and index <= status.first_subaddress + status.num_subaddresses:
                    if status.next_block >= best_next_block:
                        best_next_block = status.next_block
                        best_monitor_id = monitor_id
        if best_monitor_id:
            return best_monitor_id
        else:
            raise Exception('monitor not found')

    #
    # Utilities
    #

    """ Generate 32 bytes of entropy using a cryptographically secure RNG.
    """

    def generate_entropy(self):
        return self.stub.GenerateEntropy(empty_pb2.Empty()).entropy

    """ Get the private keys from entropy.
    """

    def get_account_key(self, entropy):
        request = api.GetAccountKeyRequest(entropy=entropy)
        return self.stub.GetAccountKey(request).account_key

    """ Returns the public address for a given monitor and index
    """
    def get_public_address(self, monitor_id, subaddress_index):
        request = api.GetPublicAddressRequest(
          monitor_id=monitor_id,
          subaddress_index=subaddress_index)
        return self.stub.GetPublicAddress(request).public_address

    """ Process a b58 request code to recover content.
    """

    def read_request_code(self, b58_code):
        request = api.ReadRequestCodeRequest(b58_code)
        response = self.stub.ReadRequestCode(request)
        return response.receiver, response.value, response.memo

    """ Prepare a "request code" used to generate a QR code for wallet apps.
    """

    def get_request_code(self, receiver, value=0, memo=""):
        request = api.GetRequestCodeRequest(receiver, value, memo)
        return self.stub.GetRequestCode(request).b58_code

    """ Process a b58 transfer code to recover content.
    """

    def read_transfer_code(self, b58_code):
        request = api.ReadTransferCodeRequest(b58_code)
        response = self.stub.ReadTransferCode(request)
        return response.entropy, response.tx_public_key, response.memo

    """ Prepare a "transfer code" used to generate a QR code for wallet apps.
    """

    def get_transfer_code(self, entropy, tx_public_key, memo=""):
        request = api.GetTransferCodeRequest(entropy, tx_public_key, memo)
        return self.stub.GetTransferCode(request).b58_code

    #
    # Transactions
    #

    """ Prepares a transaction. If the fee is zero, we use the default minimum fee. Mix-ins and other
        complexities of the MobileCoin protocol are handled automatically.
    """

    def generate_tx(self, sender_monitor_id, change_subaddress, input_list, outlay_dict, fee=0, tombstone=0):
        outlay_list = [api.Outlay(value=r['value'], receiver=r['receiver']) for r in outlay_dict]
        request = api.GenerateTxRequest(
          sender_monitor_id=sender_monitor_id,
          change_subaddress=change_subaddress,
          input_list=input_list,
          outlay_list=outlay_list,
          fee=fee)
        return self.stub.GenerateTx(request).tx_proposal

    """ Due to limits on the number of inputs allowed for a transaction, a wallet can contain
        more value than is spendable in a single transaction. This generates a self-payment
        that combines small value tx outputs together.
    """

    def generate_optimization_tx(self, sender, output_list):
        request = api.GenerateOptimizationTxRequest(sender, output_list)
        return self.stub.GenerateOptimizationTx(request).tx_proposal

    """ Prepares a transaction that can be submitted to fund a transfer code for a new
        one time account.
    """

    def generate_transfer_code_tx(self, sender, output_list, value):
        request = api.GenerateTransferCodeTxRequest(sender, output_list, value)
        response = self.stub.GenerateTransferCodeTx(request)
        return response.tx_proposal, response.entropy

    """ Submit a prepared transaction, optionall requesting a tombstone block.
    """

    def submit_tx(self, tx_proposal):
        request = api.SubmitTxRequest(tx_proposal=tx_proposal)
        response = self.stub.SubmitTx(request)
        return response.sender_tx_receipt

    #
    # Databases
    #

    """ Returns a status report for mobilecoind's ledger maintenance.
    """

    def get_ledger_info(self):
        info = self.stub.GetLedgerInfo(empty_pb2.Empty())
        return info.block_count, info.txo_count

    """ Returns a status report for a ledger block.
    """

    def get_block_info(self, block):
        request = api.GetBlockInfoRequest(block=block)
        info = self.stub.GetBlockInfo(request)
        return info.key_image_count, info.txo_count

    """ Check if a key image appears in the ledger.
    """

    def get_tx_status_as_sender(self, sender_tx_receipt):
        request = api.GetTxStatusAsSenderRequest(sender_tx_receipt)
        return self.stub.GetTxStatusAsSender(request).status

    """ Check if a transaction public key appears in the ledger.
    """

    def get_tx_status_as_receiver(self, receiver_tx_receipt):
        request = api.GetTxStatusAsReceiverRequest(receiver_tx_receipt)
        return self.stub.GetTxStatusAsReceiver(request).status
