/*
 * An application for interacting with mobilecoind
 */
package com.mobilecoin.mob_client;

import io.grpc.Channel;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import com.google.protobuf.Empty;
import com.mobilecoin.mobilecoind.MobileCoinDAPI;
import com.mobilecoin.mobilecoind.MobilecoindAPIGrpc;

public class App {
    public static void main(String[] args) {
        String target = "localhost:4444";
        ManagedChannel channel = ManagedChannelBuilder.forTarget(target)
            .usePlaintext()
            .build();
           
        var stub = MobilecoindAPIGrpc.newBlockingStub(channel);
        var entropy = stub.generateEntropy(Empty.getDefaultInstance());
        System.out.println(entropy);
    }
}
