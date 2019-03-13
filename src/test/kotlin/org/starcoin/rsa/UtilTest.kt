package org.starcoin.rsa

import org.junit.Assert
import org.junit.Test
import kotlin.random.Random

class UtilTest {

    @Test
    fun testRandomBigInteger() {
        for (i in 0..100) {
            val random1 = Random.nextBigInteger()
            val random2 = Random.nextBigInteger()
            if (random1 < random2) {
                val random3 = Random.nextBigInteger(random1, random2)
                Assert.assertTrue(random3 >= random1 && random3 < random2)
            } else {
                val random3 = Random.nextBigInteger(random2, random1)
                Assert.assertTrue(random3 >= random2 && random3 < random1)
            }
        }
    }

    @Test
    fun testHashToPrime() {
        val x = Random.nextBigInteger()
        val (h, _) = hashToPrime(x, 128)
        Assert.assertTrue(h.isProbablePrime(100))
        Assert.assertTrue(Math.log(h.toDouble()) < 128)
    }
}