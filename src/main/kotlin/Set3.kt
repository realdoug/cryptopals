import java.io.File
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

fun buildCookie() : Triple<ByteArray, ByteArray, ByteArray> {
    val idx = randbtw(0,9)
    val stringz = listOf(
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    )

    val raw = stringz[idx].toByteArray("base64")

    val initVector = randbytes(16)
    val key = randbytes(16)
    val cipher = CBC(initVector)
    val encryptedSession = cipher.encrypt(raw.pad(16), key)
    return Triple(initVector, encryptedSession, key)
}

fun validateCookie(cookie : ByteArray, initV : ByteArray, key : ByteArray) : Boolean {
    val cipher = CBC(initV)
    val session = cipher.decrypt(cookie, key)
    try{
        validatePKCS7(session)
        return true
    }catch(e : Throwable){
        return false
    }
}

fun chal17(){
    val (iv, ciphertext, key) = buildCookie()
    val input = iv + ciphertext

    var cookie = ByteArray(0)
    (0..input.size/16-2).forEach { b ->
        val nxt = b+1; val nxtnxt = b+2

        val r1 = IntRange(b*16, nxt*16-1)
        val r2 = IntRange(nxt*16, nxtnxt*16-1)

        val prev = input.sliceArray(r1)
        val block = input.sliceArray( r2 )

        var dcrblk = ByteArray(0)
        var start_guess = 0

        while(dcrblk.size < 16 ) {
            val padding = dcrblk.size + 1

            var found_block = false
            for(guess in (start_guess..255)) {
                val _iv = prev.copyOf()

                (1..padding).forEach { byte ->
                    if(byte < padding){
                        _iv[16-byte] =
                            prev[16-byte]
                                .xor(dcrblk[dcrblk.size-byte])
                                .xor(padding.toByte())
                    }else{
                        _iv[16-byte] =
                            prev[16-byte]
                                .xor(guess.toByte())
                                .xor(padding.toByte())
                    }
                }

                if(validateCookie(block, _iv, key)){
                    dcrblk = ByteArray(1, { guess.toByte() }) + dcrblk
                    start_guess = 0
                    found_block = true
                    break
                }
            }
            if(!found_block){
                start_guess = dcrblk[0].toInt() + 1
                dcrblk = dcrblk.sliceArray(IntRange(1, dcrblk.size-1))
            }
        }
        cookie += dcrblk
    }
    println(String(cookie.unpad()))
}

class CTR(val key : ByteArray){
    private val blocksize = 16
    private val nonce = ByteArray(blocksize/2, { 0.toByte() })
    var currentBlock = ByteArray(0)
    var nextStep = 0

    fun step(b : Byte) : Byte {
        val idx = nextStep.rem(blocksize)
        if(idx == 0){
            // reset the currentBlock
            val counter = nextStep.div(16)
            val relevantByte = counter.div(255)
            val input = nonce + ByteArray(8, {
                if(it == relevantByte) {
                    counter.toByte()
                }else if(it < relevantByte){
                    255.toByte()
                }else{
                    0.toByte()
                }
            })

            val cipher = Cipher.getInstance("AES/ECB/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key,"AES"))
            currentBlock = cipher.doFinal(input)
        }
        val decrypted = b.xor(currentBlock[idx])
        nextStep++
        return decrypted
    }
}

fun chal18(){
    val ciphertext = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".toByteArray("base64")
    val key = "YELLOW SUBMARINE".toByteArray("text")

    val cipher = CTR(key)
    val decryptedBytes = ciphertext.map { cipher.step(it) }
    println( String( ByteArray(decryptedBytes.size, { decryptedBytes[it] }) ))
}

fun chal19(){
    val texts =
            File("set3chal19.txt")
                    .readText()
                    .split("\n")
                    .filter { it.length > 1}
                    .map { it.toByteArray("base64") }

    val encrypted =
            texts
                    .map { ctx ->
                        val cipher = CTR("YELLOW SUBMARINE".toByteArray("text"))
                        val list = ctx.map { cipher.step(it) }
                        ByteArray(list.size, { list[it] })
                    }

    val maxlen = texts.map { it.size }.max()
    val kstream =
            (0..maxlen!!-1).map { index ->
                val bytesAtIndex = encrypted.map {
                    if(it.size > index)
                        it[index]
                    else
                        null
                }.filter { it != null }

                (0..255).maxBy { guess ->
                    val xored = bytesAtIndex.map { it!!.xor(guess.toByte()) }
                    engScore(String(ByteArray(xored.size, { xored[it] } )))
                }
            }

    val d = encrypted[20].mapIndexed { i,b -> b.xor(kstream[i]!!.toByte()) }
    println(
            String( ByteArray(d.size, { d[it] }) )
    )
}

fun chal20(){
    val texts =
            File("set3chal19.txt")
                    .readText()
                    .split("\n")
                    .filter { it.length > 1}
                    .map { it.toByteArray("base64") }

    val minlen = texts.map { it.size }.min()
    val concat = texts.map { it.take(minlen!!) }.flatten()
    val stream = repeatingKeyXor(minlen!!, ByteArray(concat.size, {concat[it]}))
    println(stream)
}

class MT19937(seed: Long, var mt: MutableList<Long> = LongRange(0, 623).toMutableList() ) {
    var index = 0
    val bitmask1 = 0xFFFFFFFF
    val bitmask2 = 0x80000000
    val bitmask3 = 0x7fffffff.toLong()
    val statesize = 624
    val lastNum = statesize-1

    init {
        mt[0] = seed
        (1..lastNum).forEach {
            val prev = mt[it-1]
            mt[it] =
                (1812433253 * prev) xor (prev shr 30 + it) and bitmask1
        }

        (0..lastNum).forEach {
            val idx2 = (it + 1).rem(statesize)
            val idx3 = (it + 397).rem(statesize)

            val y = (mt[it] and bitmask2) + (mt[idx2] and bitmask3)
            mt[it] = mt[idx3] xor (y shr 1)
            if (y.rem(2) != 0.toLong())
                mt[it] = mt[it] xor 2567483615
        }
    }

    companion object {
        fun temper(i: Long): Long {
            var y = i
            y = y xor (y ushr 11)
            y = y xor ((y shl 7) and 0x9d2c5680)
            y = y xor ((y shl(15)) and 0xefc60000)
            y = y xor (y ushr 18)
            return y
        }
    }

    fun next(): Long {
        var y = temper(mt[index])
        index = (index + 1).rem(statesize)
        return y
    }
}

fun rand(seed: Long): Long {
    return MT19937(seed).next()
}

fun chal21(){
    val randos = (0..10).map {
        val seed = System.currentTimeMillis()
        MT19937(seed).next()
    }
    println("RANDOMS: $randos")
}

fun chal22(){
    println(
        rand(100) == rand(100) &&
        rand(100) == rand(100) )

    Thread.sleep( Random().nextInt(960).toLong() )

    val seed = System.currentTimeMillis()
    val generatedRand = rand(seed)

    Thread.sleep( Random().nextInt(960).toLong() )

    val now = System.currentTimeMillis()
    val crackedSeed = (now downTo now - 2500).find { rand(it) == generatedRand }
    println(crackedSeed == seed)
}

fun unshiftRightXor(value: Long, shift: Int): Long {
    var result: Long = 0
    (0..(32/shift)).forEach {
        result = result xor (value ushr (shift*it))
    }
    return result
}

fun unshiftLeftMaskXor(value: Long, shift: Int, mask: Long): Long {
    var _value = value
    var result: Long = 0
    (0..(32/shift)).forEach {
        val partMask = (0xffffffff ushr (32-shift)) shl (shift*it)
        val part = _value and partMask
        _value = _value xor ((part shl shift) and mask)
        result = result or part
    }
    return result
}

fun untemper(y: Long): Long {
    var value = y
    value = unshiftRightXor(value, 18)
    value = unshiftLeftMaskXor(value, 15, 4022730752)
    value = unshiftLeftMaskXor(value, 7, 2636928640)
    value = unshiftRightXor(value, 11)
    return value
}

fun chal23() {
    /*listOf(100, 1337, 3730046104).forEach {
        println( it == untemper(MT19937.temper(it)) )
    }*/

    val gen = MT19937(19)
    val copy = MT19937(99)
    copy.mt = (0..623).map { untemper(gen.next()) }.toMutableList()

    println(gen.next() == copy.next())
}



fun streamCypher(seed: Short, plaintext: ByteArray): ByteArray {
    val gen = MT19937(seed.toLong())
    val byteList = plaintext.map { it xor gen.next().toByte() }
    return ByteArray(byteList.size, { byteList[it] })
}

fun chal24() {
    val orig = "AAAAAAAAAAAAAA"
    val enc = streamCypher(99, orig.toByteArray())
    val dec = streamCypher(99, enc)
    println(String(dec) == orig)


    val myInput = orig.toByteArray()
    val seed = 2131.toShort()

    val rand = MT19937(99)
    val randSaltSize = rand.next().rem(10)
    val salt = randbytes(randSaltSize.toInt())
    val encrypted = streamCypher(seed, salt + myInput)

    val crackedSeed = (0..Short.MAX_VALUE).find {
        val seedGuess = it.toShort()
        val guess = streamCypher(seedGuess, encrypted)
        String(myInput) in String(guess) // in lieu of a good subarray comparison :(
    }!!.toShort()

    println(crackedSeed == seed)
}

fun main(args : Array<String>){
    chal17()
    chal18()
    chal19()
    chal20()
    chal21()
    chal22()
    chal23()
    chal24()
}