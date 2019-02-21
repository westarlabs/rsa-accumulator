package org.starcoin.rsa

import com.google.common.hash.Hashing
import com.google.common.io.BaseEncoding
import java.math.BigInteger
import kotlin.random.Random

const val primeCertainty = 5

private val sha256 = Hashing.sha256()
private val HEX = BaseEncoding.base16().lowerCase()

fun ByteArray.toHexString() = HEX.encode(this)!!

fun Random.nextBigInteger(from: BigInteger, until: BigInteger): BigInteger {
    if (from >= until) {
        throw IllegalArgumentException("until must be greater than from")
    }
    var randomNumber: BigInteger
    val bitLength = if (from.bitLength() == until.bitLength()) from.bitLength() else this.nextInt(
        from.bitLength(),
        until.bitLength()
    )
    val random = java.util.Random()
    do {
        randomNumber = BigInteger(bitLength, random)
    } while (randomNumber < from || randomNumber >= until)
    return randomNumber
}

fun Random.nextBigInteger(until: BigInteger) = this.nextBigInteger(BigInteger.ZERO, until)

fun Random.nextBigInteger() = this.nextBigInteger(2.toBigInteger().pow(256))

fun generateLargePrime(bitLength: Int): BigInteger {
    val random = java.util.Random()
    return BigInteger.probablePrime(bitLength, random)
}

data class TwoValue<T>(val first: T, val second: T)

fun generateTwoLargeDistinctPrimes(bitLength: Int): TwoValue<BigInteger> {
    val first = generateLargePrime(bitLength)
    while (true) {
        val second = generateLargePrime(bitLength)
        if (first != second) {
            return TwoValue(first, second)
        }
    }
}

fun hashToPrime(x: BigInteger, bitLength: Int = 120, initNonce: BigInteger = BigInteger.ZERO): TwoValue<BigInteger> {
    var nonce = initNonce
    while (true) {
        val num = hashToLength(x + nonce, bitLength)
        if (num.isProbablePrime(primeCertainty)) {
            return TwoValue(num, nonce)
        }
        nonce += BigInteger.ONE
    }
}

fun hashToLength(x: BigInteger, bitLength: Int): BigInteger {
    var randomHexString = ""
    val numOfBlocks = Math.ceil(bitLength / 256.00).toInt()
    for (i in 0 until numOfBlocks) {
        randomHexString += sha256.hashBytes((x + i.toBigInteger()).toString(10).toByteArray()).asBytes()
            .toHexString()
    }

    if (bitLength % 256 > 0) {
        // # we do assume divisible by 4
        randomHexString =
            randomHexString.substring((bitLength % 256) / 4)
    }
    return BigInteger(randomHexString, 16)
}