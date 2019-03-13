package org.starcoin.rsa;

import kotlin.random.Random;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

public class RSAJavaTest {

    @Test
    public void testRSAAccumulator() {
        RSAAccumulator accumulator = new RSAAccumulator();
        BigInteger x0 = new BigInteger(Random.Default.nextBytes(128));
        BigInteger A1 = accumulator.add(x0);
        BigInteger nonce0 = accumulator.getNonce(x0);
        BigInteger proof0 = accumulator.proveMembership(x0);

        Assert.assertEquals(accumulator.getSize(), 1);
        Assert.assertEquals(accumulator.getA0(), proof0);
        Assert.assertTrue(RSAAccumulator.verifyMembership(A1, x0, nonce0, proof0, accumulator.getN()));
    }
}
