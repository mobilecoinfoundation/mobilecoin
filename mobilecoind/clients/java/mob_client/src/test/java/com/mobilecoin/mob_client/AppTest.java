/*
 * Tests for basic functionality of the protocol buffers and conversions
 */
package com.mobilecoin.mob_client;

import com.mobilecoin.mobilecoind.MobileCoinDAPI;
import com.google.protobuf.ByteString;
import com.mobilecoin.consensus.ConsensusAPI;
import org.junit.Test;
import static org.junit.Assert.*;

public class AppTest {
    @Test public void testCanCreateAccountKey() {
        byte[] b = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        var spend_key = ConsensusAPI.RistrettoPrivate.newBuilder().setData(ByteString.copyFrom(b));
        var view_key = ConsensusAPI.RistrettoPrivate.newBuilder().setData(ByteString.copyFrom(b));
        var account_key = MobileCoinDAPI.AccountKey.newBuilder().setViewPrivateKey(view_key).setSpendPrivateKey(spend_key).build();
        assert(account_key.hasViewPrivateKey());
        assert(account_key.hasSpendPrivateKey());
    }
}
