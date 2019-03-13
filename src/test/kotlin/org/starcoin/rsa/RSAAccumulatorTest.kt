package org.starcoin.rsa

import org.junit.Assert
import org.junit.Test
import kotlin.random.Random


class RSAAccumulatorTest {

    @Test
    fun testAddAndProve() {
        // first addition
        val accumulator = RSAAccumulator()
        val x0 = Random.nextBigInteger()
        val x1 = Random.nextBigInteger()

        val A1 = accumulator.add(x0)
        val nonce0 = accumulator.getNonce(x0)

        val proof0 = accumulator.proveMembership(x0)

        Assert.assertEquals(accumulator.size, 1)
        Assert.assertEquals(accumulator.A0, proof0)
        Assert.assertTrue(RSAAccumulator.verifyMembership(A1, x0, nonce0, proof0, accumulator.n))

        // second addition

        val A2 = accumulator.add(x1)
        val nonce1 = accumulator.getNonce(x1)

        val proof1 = accumulator.proveMembership(x1)

        Assert.assertEquals(accumulator.size, 2)
        Assert.assertEquals(A1, proof1)
        Assert.assertTrue(RSAAccumulator.verifyMembership(A2, x1, nonce1, proof1, accumulator.n))

        // delete
        val A3 = accumulator.delete(x0)
        val proof2 = accumulator.proveMembership(x1)
        val proofNone = accumulator.proveMembershipOrNull(x0)

        Assert.assertEquals(accumulator.size, 1)
        Assert.assertNull(proofNone)
        Assert.assertTrue(RSAAccumulator.verifyMembership(A3, x1, nonce1, proof2, accumulator.n))
    }

}