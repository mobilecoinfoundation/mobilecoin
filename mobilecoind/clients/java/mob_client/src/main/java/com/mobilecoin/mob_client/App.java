/**
 * A simple command line application for interaction with mobilecoind which also shows how to call 
 * mobilecoind from Java.
 * 
 * The `server` and `command` flags are required to generate gRPC calls. Additional parameters are required
 * depending on the command used.
 * 
 * An example invocation which simply returns a new root entropy is:
 * ./gradlew run --args='-s localhost:4444 -c entropy'
 * 
 */
package com.mobilecoin.mob_client;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;

import com.google.protobuf.ByteString;
import com.google.protobuf.Empty;
import com.mobilecoin.consensus.ConsensusAPI.KeyImage;
import com.mobilecoin.mobilecoind.MobileCoinDAPI;
import com.mobilecoin.mobilecoind.MobilecoindAPIGrpc;
import com.mobilecoin.mobilecoind.MobileCoinDAPI.AccountKey;
import com.mobilecoin.mobilecoind.MobilecoindAPIGrpc.MobilecoindAPIBlockingStub;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.cli.*;

public class App {
    public static void main(String[] args) {
        Options options = new Options();
        Option serverOption = new Option("s", "server", true, "hostname:port to connect to mobilecoind");
        serverOption.setRequired(true);
        options.addOption(serverOption);

        Option commandOption = new Option("c", "command", true, "Command to run");
        commandOption.setRequired(true);
        options.addOption(commandOption);

        Option entropyOption = new Option("e", "entropy", true, "Root entropy key for the account");
        options.addOption(entropyOption);

        Option monitorOption = new Option("m", "monitor", true, "Monitor ID");
        options.addOption(monitorOption);

        Option indexOption = new Option("i", "index", true, "Subaddress Index");
        options.addOption(indexOption);

        Option recipientOption = new Option("r", "recipient", true, "b58 code for recipient of a transfer");
        options.addOption(recipientOption);

        Option amountOption = new Option("a", "amount", true, "amount in picoMOB to transfer");
        options.addOption(amountOption);

        Option transferReceiptOption = new Option("t", "transfer-receipt", true, "receipt code for transfer status");
        options.addOption(transferReceiptOption);

        // It is assumed that mobilecoind and clients such as this will run on the same machine, however
        // there may be cases where a remote SSL connection is required
        Option sslOption = new Option("ssl", "Use SSL to connect to mobilecoind");
        options.addOption(sslOption);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);
        } catch (Exception e) {
            // Prints the error and the help message for the CLI
            System.out.println(e.getMessage());
            formatter.printHelp("mob_client", options);
            System.exit(1);
        }

        // Build a blocking gRPC connection
        String target = cmd.getOptionValue("server");
        ManagedChannel channel;
        if (cmd.hasOption("ssl")) {
            channel = ManagedChannelBuilder.forTarget(target).build();
        } else {
            channel = ManagedChannelBuilder.forTarget(target).usePlaintext().build();
        }
        var stub = MobilecoindAPIGrpc.newBlockingStub(channel);

        // Account keys are generated from root entropy, passed in as hex parameters
        // on the command line
        AccountKey accountKey = null;
        String entropy = cmd.getOptionValue("entropy");
        if (entropy != null) {
            try {
                accountKey = getKeyFromHexEntropy(stub, entropy);
            } catch (DecoderException e) {
                System.out.println("entropy was not a valid hex string");
                System.exit(1);
            }
        }

        // Monitor ID is passed in as a hex string on the command line, would generally
        // be the value returned from creating a monitor
        ByteString monitorId = null;
        String monitor = cmd.getOptionValue("monitor");
        if (monitor != null) {
            try {
                monitorId = ByteString.copyFrom(Hex.decodeHex(monitor));
            } catch (DecoderException e) {
                System.out.println("monitor was not a valid hex string");
                System.exit(1);
            }
        }

        // Subaddress index defaults to zero, can be passed using the --index flag
        long index = 0;
        String indexStr = cmd.getOptionValue("index");
        if (indexStr != null) {
            index = Long.parseLong(indexStr);
        }

        // Recipient is a b58 code representing a public address
        String recipient = cmd.getOptionValue("recipient");

        // Amount should be a positive integer which is required for transfers
        long amount = 0;
        String amountStr = cmd.getOptionValue("amount");
        if (amountStr != null) {
            amount = Long.parseLong(amountStr);
            if (amount <= 0) {
                System.out.println("amount must be a positive integer");
                System.exit(1);
            }
        }

        // Transfer Receipt consists of a hex-ecoded key image an a tombstone block
        ByteString transferKeyImage = null;
        long tombstoneBlock = 0;
        String transerReceiptStr = cmd.getOptionValue("transfer-receipt");
        if (transerReceiptStr != null) {
            String[] parts = transerReceiptStr.split(":");
            if (parts.length != 2) {
                System.out.println("The transfer receipt format is KEYIMAGE:TOMBSTONE");
                System.exit(1);
            }
            try {
                transferKeyImage = ByteString.copyFrom(Hex.decodeHex(parts[0]));
                tombstoneBlock = Long.parseLong(parts[1]);
            } catch (Exception e) {
                System.out.println("The transfer receipt format is KEYIMAGE:TOMBSTONE");
                System.exit(1);
            }
        }

        // All the functions return strings which are printed as the result to the CLI
        // tool
        String output = "";
        switch (cmd.getOptionValue("command")) {
            case "generate-entropy":
                output = getEntropy(stub);
                break;
            case "monitor":
                if (accountKey == null) {
                    output = "key flag is required for a montior";
                } else {
                    output = createMonitor(stub, accountKey);
                }
                break;
            case "balance":
                if (monitorId == null) {
                    output = "balance check requires a monitor";
                } else {
                    output = getBalance(stub, monitorId, index);
                }
                break;
            case "request":
                if (monitorId == null) {
                    output = "request code requires a monitor";
                } else {
                    output = getRequestCode(stub, monitorId, index);
                }
                break;
            case "transfer":
                if (monitorId == null || recipient == null || amount == 0) {
                    output = "transfer requires a monitor, recipient and amount";
                } else {
                    output = transfer(stub, monitorId, index, recipient, amount);
                }
                break;
            case "status":
                if (transferKeyImage == null) {
                    output = "status requires a transfer receipit";
                } else {
                    output = transferStatus(stub, transferKeyImage, tombstoneBlock);
                }
                break;
            default:
                output = "Command not recognized";
                break;
        }
        System.out.println(output);
    }

    /**
     * Calls mobilecoind to derive the AccountKey object from a hex form of the root
     * entropy
     * 
     * @param stub    The gRPC stub connected to mobilecoind
     * @param entropy A hex representation of the 256 bits of root entropy
     * @return An account key derived from the root entropy
     * @throws DecoderException If the provided entropy is not valid hex
     */
    public static AccountKey getKeyFromHexEntropy(MobilecoindAPIBlockingStub stub, String entropy)
            throws DecoderException {
        var b = ByteString.copyFrom(Hex.decodeHex(entropy));
        var request = MobileCoinDAPI.GetAccountKeyRequest.newBuilder().setEntropy(b).build();
        return stub.getAccountKey(request).getAccountKey();
    }

    /**
     * Generates 256-bits of random entropy that can be used to create a new account
     * key
     * 
     * @param stub The gRPC stub connected to mobilecoind
     * @return A hex representation of random 256 bits
     */
    static String getEntropy(MobilecoindAPIBlockingStub stub) {
        var entropy = stub.generateEntropy(Empty.getDefaultInstance()).getEntropy();
        return Hex.encodeHexString(entropy.toByteArray());
    }

    /**
     * Creates a monitor over a single account key and a range of subaddresses TODO:
     * this is fixed to monitor 100,000 subaddresses
     * 
     * @param stub       The gRPC stub connected to mobilecoind
     * @param accountKey An AccountKey object, usually returned by
     *                   getKeyFromHexEntropy
     * @return A hex string representation of the monitor ID which can be used for
     *         balance and transfer
     */
    static String createMonitor(MobilecoindAPIBlockingStub stub, AccountKey accountKey) {
        var request = MobileCoinDAPI.AddMonitorRequest.newBuilder().setAccountKey(accountKey).setFirstSubaddress(0)
                .setNumSubaddresses(100000).build();
        var monitor = stub.addMonitor(request);
        return Hex.encodeHexString(monitor.getMonitorId().toByteArray());
    }

    /**
     * Gets the balance for a given monitor and subaddress index
     * 
     * @param stub      The gRPC stub connected to mobilecoind
     * @param monitorId 256-bit ID of the monitor observing the account
     * @param index     The subaddress index for which to check the balance
     * @return A string representing the current balance for the account
     */
    static String getBalance(MobilecoindAPIBlockingStub stub, ByteString monitorId, long index) {
        var request = MobileCoinDAPI.GetBalanceRequest.newBuilder().setMonitorId(monitorId).setSubaddressIndex(index)
                .build();
        var balance = stub.getBalance(request).getBalance();
        return Long.toString(balance);
    }

    /**
     * Given a monitor ID and subaddress index, generates the b58 request code (public address)
     * for a payment
     *
     * @param stub      The gRPC stub connected to mobilecoind
     * @param monitorId 256-bit ID of the monitor observing the account
     * @param index     The subaddress index for which get the request code
     * @return A b58 encoded string specifying a target public address
     */
    static String getRequestCode(MobilecoindAPIBlockingStub stub, ByteString monitorId, long index) {
        // First get the public address
        var paRequest = MobileCoinDAPI.GetPublicAddressRequest.newBuilder().setMonitorId(monitorId).setSubaddressIndex(index).build();
        var publicAddress = stub.getPublicAddress(paRequest).getPublicAddress();

        // Generates a payment address with no specific request value
        var rcRequest = MobileCoinDAPI.GetRequestCodeRequest.newBuilder().
            setReceiver(publicAddress).
            build();

        return stub.getRequestCode(rcRequest).getB58Code();
    }

    /**
     * Creates a transfer to a given b58 request code for a stated amount
     * @param stub      The gRPC stub connected to mobilecoind
     * @param monitorId 256-bit ID of the monitor from which funds should be drawn
     * @param index     The subaddress index from which the funds should be drawn
     * @param requestCode The requestCode to which funds should be sent
     * @param amount The amount of picoMOB to be sent
     * @return A string to use in a future call to see if the transfer succeeded, consisting of KEYIMAGE:TOMBSTONE
     */
    static String transfer(MobilecoindAPIBlockingStub stub, ByteString monitorId, long index, String requestCode, long amount) {
        // Convert the b58 code into a public address
        var rcRequest = MobileCoinDAPI.ReadRequestCodeRequest.newBuilder().setB58Code(requestCode).build();
        var publicAddress = stub.readRequestCode(rcRequest).getReceiver();

        // Generate a single outlay for the given amount
        var outlay = MobileCoinDAPI.Outlay.newBuilder().setReceiver(publicAddress).setValue(amount);

        // Send a payment
        var spRequest = MobileCoinDAPI.SendPaymentRequest.newBuilder().setSenderMonitorId(monitorId).addOutlayList(outlay).setSenderSubaddress(index).build();
        MobileCoinDAPI.SenderTxReceipt txReceipt = null;
        try {
            txReceipt = stub.sendPayment(spRequest).getSenderTxReceipt();
        } catch (Exception e) {
            System.out.println("Your payment failed with error " + e.getMessage());
            System.exit(1);
        }

        // Generate a transaction receipt using the first key image and the tombstone block
        return Hex.encodeHexString(txReceipt.getKeyImageList(0).getData().toByteArray()) + ":" + txReceipt.getTombstone();
    }
    /**
     * Checks the status of a transfer given a key image and a tombstone block
     * @param stub            The gRPC stub connected to mobilecoind
     * @param keyImage        Bytes of any of the key images used in the transaction
     * @param tombstoneBlock  The tombstone block for the transaction
     * @return A string representing the current status of the transaction, one of 'Unknown', 'Verified' or 'TombstoneBlockExceeded'
     */
    static String transferStatus(MobilecoindAPIBlockingStub stub, ByteString keyImageBytes, long tombstoneBlock) {
        var keyImage = com.mobilecoin.api.MobileCoinAPI.KeyImage.newBuilder().setData(keyImageBytes).build();
        var receipt = MobileCoinDAPI.SenderTxReceipt.newBuilder().addKeyImageList(keyImage).setTombstone(tombstoneBlock).build();
        //var receipt = MobileCoinDAPI.SenderTxReceipt.newBuilder().setTombstone(tombstoneBlock).build();
        var request = MobileCoinDAPI.GetTxStatusAsSenderRequest.newBuilder().setReceipt(receipt).build();

        var status = stub.getTxStatusAsSender(request).getStatus();

        return status.toString();
    }
}
