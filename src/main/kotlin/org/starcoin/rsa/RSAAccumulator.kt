package org.starcoin.rsa

import java.math.BigInteger
import kotlin.random.Random

class RSAAccumulator {

    companion object {
        //RSA key size for 128 bits of security (modulu size)
        private const val RSA_KEY_SIZE = 3072
        private const val RSA_PRIME_SIZE = RSA_KEY_SIZE / 2
        //taken from: LLX, "Universal accumulators with efficient nonmembership proofs", construction 1
        private const val ACCUMULATED_PRIME_SIZE = 128
    }

    val A0: BigInteger
    var A: BigInteger
        private set
    val n: BigInteger
    private val data = mutableMapOf<BigInteger, BigInteger>()

    val size: Int
        get() = this.data.size

    init {
        val (p, q) = generateTwoLargeDistinctPrimes(RSA_PRIME_SIZE)
        n = p * q
        // draw random number within range of [0,n-1]
        A0 = Random.nextBigInteger(BigInteger.ZERO, n)
        A = A0
    }

    fun getNonce(x: BigInteger): BigInteger? {
        return data[x]
    }

    fun add(x: BigInteger): BigInteger {
        if (data.containsKey(x)) {
            return A
        } else {
            val (hashPrime, nonce) = hashToPrime(x, ACCUMULATED_PRIME_SIZE)
            A = A.modPow(hashPrime, n)
            data[x] = nonce
            return A
        }
    }

    fun proveMembership(x: BigInteger): BigInteger? {
        return if (!data.containsKey(x)) {
            null
        } else {
            var product = BigInteger.ONE
            for ((k, v) in data) {
                if (k != x) {
                    product *= hashToPrime(k, ACCUMULATED_PRIME_SIZE, v).first
                }
            }
            A0.modPow(product, n)
        }
    }

    fun verifyMembership(x: BigInteger, nonce: BigInteger, proof: BigInteger): Boolean {
        return this.doVerifyMembership(hashToPrime(x, ACCUMULATED_PRIME_SIZE, nonce).first, proof)
    }

    private fun doVerifyMembership(x: BigInteger, proof: BigInteger): Boolean {
        return proof.modPow(x, n) == A
    }

    fun delete(x: BigInteger): BigInteger {
        return if (!data.containsKey(x)) {
            A
        } else {
            data.remove(x)
            var product = BigInteger.ONE
            for ((k, v) in data) {
                if (k != x) {
                    product *= hashToPrime(k, ACCUMULATED_PRIME_SIZE, v).first
                }
            }
            this.A = A0.modPow(product, n)
            A
        }
    }

}