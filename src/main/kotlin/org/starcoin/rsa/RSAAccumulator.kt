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

        @JvmStatic
        fun verifyMembership(
            A: BigInteger,
            x: BigInteger,
            nonce: BigInteger,
            proof: BigInteger,
            n: BigInteger
        ): Boolean {
            return this.doVerifyMembership(A, hashToPrime(x, ACCUMULATED_PRIME_SIZE, nonce).first, proof, n)
        }

        private fun doVerifyMembership(A: BigInteger, x: BigInteger, proof: BigInteger, n: BigInteger): Boolean {
            return proof.modPow(x, n) == A
        }
    }

    val A0: BigInteger
    private var A: BigInteger
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

    fun getNonce(x: BigInteger): BigInteger {
        return data.getValue(x)
    }

    fun getNonceOrNull(x: BigInteger): BigInteger? {
        return data[x]
    }

    fun add(x: BigInteger): BigInteger {
        return if (data.containsKey(x)) {
            A
        } else {
            val (hashPrime, nonce) = hashToPrime(x, ACCUMULATED_PRIME_SIZE)
            A = A.modPow(hashPrime, n)
            data[x] = nonce
            A
        }
    }

    fun proveMembership(x: BigInteger): BigInteger {
        return this.proveMembershipOrNull(x) ?: throw NoSuchElementException("Can not find member $x")
    }

    fun proveMembershipOrNull(x: BigInteger): BigInteger? {
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