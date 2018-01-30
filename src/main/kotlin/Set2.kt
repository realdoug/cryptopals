import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

val unknown = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".toByteArray("base64")

class IllegalPaddingException(override var message:String): Exception()

fun validatePKCS7(input : ByteArray) : Boolean {
    val padSize = input.last().toInt()

    input
            .reversed()
            .take(padSize)
            .forEach {
                if(it.toInt() != padSize)
                    throw IllegalPaddingException("Invalid PKCS7 Padding")
            }

    return true
}

fun ByteArray.pad(num : Int) : ByteArray {
    val diff = num - this.size.rem(num)
    val padding = ByteArray(diff, { diff.toByte() })
    return this + padding
}

fun ByteArray.unpad() : ByteArray {
    val padNum = this[this.size-1].toInt()
    val unpadded = this.take(this.size-padNum)
    return ByteArray(unpadded.size, { unpadded[it] })
}

class CBC(_iv : ByteArray) {
    private val blocksize = 16
    val cipher = Cipher.getInstance("AES/ECB/NoPadding")
    val iv = _iv

    fun _blox(inp : ByteArray) : List<ByteArray> {
        return (
                inp
                        .withIndex()
                        .groupBy { it.index / blocksize }
                        .map { it.value.map { it.value } }
                        .map { bList -> ByteArray(bList.size, { bList[it] }) }
                )
    }

    fun encrypt(txt : ByteArray, key : ByteArray) : ByteArray {
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))

        val blox = _blox(txt)
        var prev = iv
        var retVal = ByteArray(0)
        blox.forEach { block ->
            val xoredBytes = block.mapIndexed { i,b -> b.xor(prev[i]) }
            val newBlock = cipher.doFinal( ByteArray(xoredBytes.size, { xoredBytes[it] }) )
            retVal += newBlock
            prev = newBlock
        }

        return retVal
    }

    fun decrypt(txt : ByteArray, key : ByteArray) : ByteArray {
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"))

        val blox = _blox(txt)
        var prev = iv
        var retVal = ByteArray(0)
        blox.forEach { block ->
            val newBlock =
                    cipher
                            .doFinal(block)
                            .mapIndexed { i,b -> b.xor(prev[i]) }

            retVal += newBlock
            prev = block
        }

        return retVal
    }
}

fun chal9() {
    val inp = "YELLOW SUBMARINE".toByteArray("text")
    val out = inp.pad(20 )
    println(out.size == 20)
}

fun chal10(){
    val key = "YELLOW SUBMARINE".toByteArray("text")
    val input = File("set2chal10.txt").readText().toByteArray("base64")
    val c = CBC(ByteArray(16, { 0.toByte() }))

    val dec = c.decrypt(input, key)

    val testVal = "AnythingAnything"
    val enc = c.encrypt(testVal.toByteArray("text"), key)

    println(String(dec).contains("I'm back and I'm ring") && testVal == String(c.decrypt(enc, key)))
}

fun randbytes(count : Int) : ByteArray {
    return ByteArray(count, { randbtw(0,255).toByte() })
}

fun randbtw(start : Int, end : Int) : Int {
    return SecureRandom().nextInt(end - start) + start
}

fun encryptionOracle(input : ByteArray) : Pair<Int,ByteArray> {
    val k = randbytes(16)
    val prepend = randbytes( randbtw(5,10) )
    val append  = randbytes( randbtw(5,10) )
    val mode = randbtw(0,1) // 0 = ecb 1 = cbc

    val oracleInput = prepend + input + append

    if(mode == 0){ // cbc
        val cipher = CBC(randbytes(16))
        return Pair(mode, cipher.encrypt(oracleInput.pad(16), k))
    }else{ // ecb
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"))
        return Pair(mode, cipher.doFinal(oracleInput))
    }
}

fun chal11(){
    val (mode, output) = encryptionOracle("YELLOW SUBMARINEYELLOW SUBMARINE".toByteArray("text"))
    val prediction = if(detectECB(output)) 1 else 0
    println(prediction === mode)
}

class NewOracle(unknown : ByteArray, keyInput : ByteArray = randbytes(16), randPrefix : Boolean = false) {
    val unknown = unknown
    val key = SecretKeySpec(keyInput, "AES")
    val prefix = if(randPrefix) randbytes(randbtw(16, 32)) else ByteArray(0)

    fun encrypt(input : ByteArray) : ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, key)

        return cipher.doFinal( (prefix + input + unknown) )
    }

    fun decrypt(input : ByteArray) : ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, key)
        return cipher.doFinal(input)
    }

    fun createProfile(email : String) : ByteArray {
        if(email.contains("&") || email.contains("="))
            throw IllegalArgumentException("Illegal characters in email")

        val profile =
                mapOf(
                        "email" to email,
                        "uid" to 10,
                        "role" to "user")
                        .map {
                            val (k, v) = it
                            "$k=$v"
                        }
                        .joinToString("&")
                        .toByteArray("text")

        return this.encrypt(profile)
    }
}

fun findBlockSize(oracle : NewOracle) : Int {
    var compareEncrypted = oracle.encrypt(ByteArray(0))
    var i = 1
    var c1 = 0
    while(true){
        val testEncrypted = oracle.encrypt(ByteArray(i, { 0.toByte() }))
        if(testEncrypted.size != compareEncrypted.size)
            return testEncrypted.size - compareEncrypted.size

        i++
    }
}

fun crackAES(or : NewOracle, blocksize : Int, prefixSize : Int) : ByteArray {
    var unknownDecrypted = ByteArray(0)
    val pad = blocksize - prefixSize.rem(blocksize)

    unknown.forEachIndexed { i,unknownB ->
        val attackSize = pad + (blocksize-1)-i.rem(blocksize)
        val attack = ByteArray(attackSize, { 0.toByte() })
        val known = attack + unknownDecrypted

        val answerMap =
                (0..255).associate {
                    val b = it.toByte()
                    val guess = ByteArray(1, { b })
                    val ans =
                            or
                                    .encrypt(known+guess)
                                    .drop(prefixSize)
                                    .take(known.size+1)
                    ans to b
                }

        val output = or.encrypt(attack).drop(prefixSize)
        val k = output.take(known.size+1)
        unknownDecrypted += ByteArray(1, { answerMap[k]!! })
    }

    return unknownDecrypted
}

fun chal12(){
    val or = NewOracle(unknown)

    val blocksize = findBlockSize(or)
    println(blocksize == 16)
//    println(detectECB(or.encrypt("YELLOW SUBMARINEYELLOW SUBMARINE".toByteArray("text"))))

    val unknownDecrypted = crackAES(or, blocksize, 0)

//    println(String(unknownDecrypted))
    println(String(unknownDecrypted) == String(unknown))
}

fun str2map(qstr : String) : Map<String,String> {
    return (
            qstr
                    .split("&")
                    .associate {
                        val kval = it.split("=")
                        if(kval.size == 2)
                            kval[0] to kval[1]
                        else
                            "<NONE>" to "<NONE>"
                    })
}

fun chal13() {
    val oracle = NewOracle(ByteArray(0))
    val encrypted = oracle.createProfile("doug@test.com")
    val decrypted = String( oracle.decrypt(encrypted) )
//    println( str2map(decrypted) )

    val str1Input = "doug@g.comadmin".toByteArray("text") + ByteArray(11, { 11.toByte() })
    val str1 = oracle.createProfile(String(str1Input))
    val str2 = oracle.createProfile("myrealemail+12345678@test.com")

    val fake1 = str1.copyOfRange(16,32)
    val fake2 = str2.copyOfRange(0,48)

    val forcedAdmin = str2map(String( oracle.decrypt(fake2 + fake1) ))

    println(forcedAdmin["role"] == "admin")
}

fun chal14() {
    val oracle = NewOracle(unknown = unknown, randPrefix = true)
    val blocksize = findBlockSize(oracle)

    val inp1 = oracle.encrypt(ByteArray(0))
    val inp2 = oracle.encrypt(ByteArray(1, { 0.toByte() }))

    var prefixSize = 0
    for(mod in (0..blocksize)) {
        val attack = ByteArray(blocksize*4+mod, { 0.toByte() })
//        println(attack.size)
        val result = oracle.encrypt(attack)
//        println(result.size)
        val blox =
                result
                        .withIndex()
                        .groupBy { it.index / blocksize }
                        .map { it.value.map { it.value } }
//        println(blox.size)


        var done = false
        var i = 0
        for(b in blox){
            if(i < blox.size-4 && b == blox[i+1] && b == blox[i+2] && b == blox[i+3]){
                prefixSize = i*blocksize-mod
                done = true
                break
            }
            i++
        }
        if(done) break

    }

    val answer = crackAES(oracle, blocksize, prefixSize)
    println( String(answer) == String(unknown) )
}

fun chal15(){
    val input = "ICEICEBABY".toByteArray("text") + ByteArray(4, { 4.toByte() })
    println(validatePKCS7(input))
}

fun chal16(){
    val pre = "comment1=cooking%20MCs;userdata=".toByteArray("text")
    val post = ";comment2=%20like%20a%20pound%20of%20bacon".toByteArray("text")
    val cipher = CBC(randbytes(16))
    val key = randbytes(16)

    val attackInput = pre + "?admin?true?".toByteArray("text") + post
    var encrypted = cipher.encrypt(attackInput.pad(16), key)

    encrypted[16] = encrypted[16].xor(4)
    encrypted[22] = encrypted[22].xor(2)
    encrypted[27] = encrypted[27].xor(4)

    val dec = String( cipher.decrypt(encrypted, key) )
    println(dec.contains(";admin=true;"))

}


fun main(args: Array<String>){
    chal9()
    chal10()
    chal11()
    chal12()
    chal13()
    chal14()
    chal15()
    chal16()
}