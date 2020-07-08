# Copyright (c) 2018-2020 MobileCoin Inc.

import external_pb2
import blockchain_pb2
from google.protobuf import empty_pb2
import grpc
import mobilecoind_api_pb2 as api
import mobilecoind_api_pb2_grpc as api_grpc

from random import randint


class MonitorNotFound(Exception):
    """ When a Monitor is not Found"""
    pass


class mob_client:
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
        self.stub = api_grpc.MobilecoindAPIStub(self.channel)

    def __del__(self):
        """ Close the gRPC connection upon deletion."""
        try:
            self.channel.close()
        except Exception:
            pass

    def add_monitor(self,
                    account_key,
                    first_subaddress=0,
                    num_subaddresses=100000,
                    first_block=0):
        """ Create a process that watches the ledger for tx outputs belonging to a
        set of subaddresses, each specified by account_key and an index.
        """
        request = api.AddMonitorRequest(account_key=account_key,
                                        first_subaddress=first_subaddress,
                                        num_subaddresses=num_subaddresses,
                                        first_block=first_block)
        return self.stub.AddMonitor(request).monitor_id

    def remove_monitor(self, monitor_id):
        """ Remove an existing monitor and delete any data it has stored.
        """
        request = api.RemoveMonitorRequest(monitor_id=monitor_id)
        return self.stub.RemoveMonitor(request)

    def get_monitor_list(self):
        """ Returns a list of all active monitors.
        """
        return self.stub.GetMonitorList(empty_pb2.Empty()).monitor_id_list

    def get_monitor_status(self, monitor_id):
        """ Returns a status report for a monitor process.
        """
        request = api.GetMonitorStatusRequest(monitor_id=monitor_id)
        response = self.stub.GetMonitorStatus(request)
        return response.status

    def get_unspent_tx_output_list(self, monitor_id, index=0):
        """ Returns the list of tx outputs collected for a subaddress.
        """
        request = api.GetUnspentTxOutListRequest(monitor_id=monitor_id,
                                                 subaddress_index=index)
        response = self.stub.GetUnspentTxOutList(request)
        return response.output_list

    def get_balance(self, monitor_id, index=0):
        """ Returns the sum of unspent tx outputs collected for a subaddress.
        """
        uoutput_list = self.get_unspent_tx_output_list(monitor_id, index)
        balance = 0
        for utxo in uoutput_list:
            balance += utxo.value
        return balance

    def get_monitor_id(self, account_key, index=0):
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
                if index >= status.first_subaddress and index <= status.first_subaddress + status.num_subaddresses:
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

    def get_account_key(self, entropy):
        """ Get the private keys from entropy.
        """
        request = api.GetAccountKeyRequest(entropy=entropy)
        return self.stub.GetAccountKey(request).account_key

    def get_public_address(self, monitor_id, subaddress_index):
        """ Returns the public address for a given monitor and index
        """
        request = api.GetPublicAddressRequest(
            monitor_id=monitor_id, subaddress_index=int(subaddress_index))
        return self.stub.GetPublicAddress(request).public_address

    def read_request_code(self, b58_code):
        """ Process a b58 request code to recover content.
        """
        request = api.ReadRequestCodeRequest(b58_code=b58_code)
        response = self.stub.ReadRequestCode(request)
        return response.receiver, response.value, response.memo

    def get_request_code(self, receiver, value=0, memo=""):
        """ Prepare a "request code" used to generate a QR code for wallet apps.
        """
        request = api.GetRequestCodeRequest(receiver=receiver,
                                            value=value,
                                            memo=memo)
        return self.stub.GetRequestCode(request).b58_code

    def read_transfer_code(self, b58_code):
        """ Process a b58 transfer code to recover content.
        """
        request = api.ReadTransferCodeRequest(b58_code=b58_code)
        response = self.stub.ReadTransferCode(request)
        return response.entropy, response.tx_public_key, response.memo

    def get_transfer_code(self, entropy, tx_public_key, memo=""):
        """ Prepare a "transfer code" used to generate a QR code for wallet apps.
        """
        request = api.GetTransferCodeRequest(entropy=entropy,
                                             tx_public_key=tx_public_key,
                                             memo=memo)
        return self.stub.GetTransferCode(request).b58_code

    #
    # Transactions
    #

    def generate_tx(self,
                    sender_monitor_id,
                    change_subaddress,
                    input_list,
                    outlay_dict,
                    fee=0,
                    tombstone=0):
        """ Prepares a transaction. If the fee is zero, we use the default minimum fee. Mix-ins and other
        complexities of the MobileCoin protocol are handled automatically.
        """
        outlay_list = [
            api.Outlay(value=r['value'], receiver=r['receiver'])
            for r in outlay_dict
        ]
        request = api.GenerateTxRequest(sender_monitor_id=sender_monitor_id,
                                        change_subaddress=change_subaddress,
                                        input_list=input_list,
                                        outlay_list=outlay_list,
                                        fee=fee,
                                        tombstone=tombstone)
        return self.stub.GenerateTx(request).tx_proposal

    def generate_optimization_tx(self, monitor_id, subaddress):
        """ Due to limits on the number of inputs allowed for a transaction, a wallet can contain
        more value than is spendable in a single transaction. This generates a self-payment
        that combines small value tx outputs together.
        """
        request = api.GenerateOptimizationTxRequest(monitor_id=monitor_id,
                                                    subaddress=subaddress)
        return self.stub.GenerateOptimizationTx(request).tx_proposal

    def generate_transfer_code_tx(self, sender_monitor_id, change_subaddress,
                                  input_list, value, fee, tombstone, memo):
        """ Prepares a transaction that can be submitted to fund a transfer code for a new
        one time account.
        """
        request = api.GenerateTransferCodeTxRequest(
            sender_monitor_id=sender_monitor_id,
            change_subaddress=change_subaddress,
            input_list=input_list,
            value=value,
            fee=fee,
            tombstone=tombstone,
            memo=memo)
        response = self.stub.GenerateTransferCodeTx(request)
        return response.tx_proposal, response.entropy

    def submit_tx(self, tx_proposal):
        """ Submit a prepared transaction, optionall requesting a tombstone block.
        """
        request = api.SubmitTxRequest(tx_proposal=tx_proposal)
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

    def get_block_info(self, block):
        """ Returns a status report for a ledger block.
        """
        request = api.GetBlockInfoRequest(block=block)
        info = self.stub.GetBlockInfo(request)
        return info.key_image_count, info.txo_count

    def get_block(self, block):
        """ Returns detailed information for a ledger block.
        """
        request = api.GetBlockRequest(block=block)
        block_contents = self.stub.GetBlock(request)
        return block_contents

    def get_tx_status_as_sender(self, sender_tx_receipt):
        """ Check if a key image appears in the ledger.
        """
        request = api.GetTxStatusAsSenderRequest(receipt=sender_tx_receipt)
        response = self.stub.GetTxStatusAsSender(request)
        return response.status

    def get_tx_status_as_receiver(self, receiver_tx_receipt):
        """ Check if a transaction public key appears in the ledger.
        """
        request = api.GetTxStatusAsReceiverRequest(receipt=receiver_tx_receipt)
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