import org.apache.commons.codec.binary.*
import org.apache.commons.codec.binary.Base64
import kotlin.experimental.xor
import java.io.File
import java.security.MessageDigest
import java.util.*
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.SecretKey
import javax.crypto.spec.PBEKeySpec
import java.security.spec.KeySpec
import javax.crypto.SecretKeyFactory



fun String.toByteArray(encoding: String) : ByteArray{
    return when(encoding) {
        "hex" -> Hex.decodeHex(this.toCharArray())
        "text" -> this.toCharArray().map { it.toByte() }.toByteArray()
        "base64" -> Base64.decodeBase64(this)
        else -> ByteArray(0)
    }
}

fun chal1(){
    val inp = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    val out = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    val bytes = inp.toByteArray("hex")
    println(Base64.encodeBase64String(bytes) == out)
}

fun chal2(){
    val inp = "1c0111001f010100061a024b53535009181c"
    val cmp = "686974207468652062756c6c277320657965"
    val res = "746865206b696420646f6e277420706c6179"

    val inpBytes = inp.toByteArray("hex")
    val cmpBytes = cmp.toByteArray("hex")

    val retBytes = ByteArray(inpBytes.size);
    for((idx, b) in inpBytes.withIndex()){
        retBytes.set(idx, b.xor(cmpBytes[idx]))
    }

    println(Hex.encodeHexString(retBytes) == res)
}

fun engScore(input : String) : Int {
    val scores : List<Int> = input.toCharArray().map {
        var score : Int = 0
        val ch = it.toString().toLowerCase()
        if(ch == " " || ch == "e" || ch == "t" || ch == "a" ||
           ch == "o" || ch == "i" || ch == "n" || ch == "s" ||
           ch == "h" || ch == "r" || ch == "d" || ch == "l" ||
           ch == "u"
        ) score++
        //ETAOIN SHRDLU
        score
    }
    return scores.sum()
}

fun singleCharXOR(msgBytes : ByteArray) : Pair<String, Byte>{
    var score = 0
    var decoded = ""
    var key = 0.toChar().toByte()
    (0..255).map {
        val asciiChar = it.toChar()
        var msg = msgBytes.map { c ->
            asciiChar.toByte().xor(c).toChar()
        }.joinToString("")
        var _score = engScore(msg)
        if(_score > score){
            score = _score
            decoded = msg
            key = it.toChar().toByte()
        }
    }
    return Pair(decoded, key)
}

fun chal3(){
    val msg = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    println(singleCharXOR(msg.toByteArray("hex")))
}

fun chal4(){
    with( File("set1chal4.txt") ){
        inputStream()
        bufferedReader()
        useLines { lines ->
            val ans = lines.maxBy {
                val (decoded, key) = singleCharXOR(it.toByteArray("hex"))
                engScore(decoded)
            }
            println( singleCharXOR(ans!!.toByteArray("hex")) )
        }
    }
}

fun chal5(){
    val input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    val ans = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    val key = "ICE".toList()

    val outputBytes =
        with(input) {
            toCharArray()
            map { it.toByte() }
            .mapIndexed { i, ch ->
                val compare = key[i.rem(3)].toByte()
                ch.xor(compare)
            }
        }
    val encoded =
        Hex.encodeHexString(
            ByteArray(outputBytes.size, { outputBytes[it] }))
    println(ans == encoded)
}

fun hammingDistance(input : ByteArray, compare : ByteArray) : Int {
    var sum = 0
    input.zip(compare) { a, b ->
        val diff = a.xor(b).toInt()
        (0..7).forEach { it : Int ->
            sum += (diff shr it) and 1
        }
    }
    return sum
}

fun testHammingDistance(){
    val inp = "this is a test".toByteArray("text")
    val cmp = "wokka wokka!!!".toByteArray("text")

    println(hammingDistance(inp,cmp) == 37)
}

fun chal6(){
    val inputBytes =
        File("set1chal6.txt").readText().toByteArray("base64")

    val guesses = (2..40).map { ksize ->
        val chunks =
            inputBytes
            .withIndex()
            .groupBy { it.index / ksize }
            .map { it.value.map { it.value } }

        val scores = (0..6).map { num ->
            val chunk1 = ByteArray(chunks[num].size, { chunks[num][it] })
            val chunk2 = ByteArray(chunks[num].size, { chunks[num+1][it] })

            hammingDistance(chunk1, chunk2)
        }

        val dist = scores.sum().div(ksize.toFloat())
        Pair(ksize, dist)
    }
    .sortedBy { it.second }
    .take(5)

    val answer = guesses.map { (ksize, _) ->
        var blox = mutableMapOf<Int, ArrayList<Byte>>()
        (0..(ksize - 1)).forEach { blox.put(it, ArrayList(0)) }
        inputBytes
                .withIndex()
                .groupBy { it.index / ksize }
                .map { it.value.map { it.value } }
                .forEach { chunk ->
                    chunk.forEachIndexed { i, b -> blox[i]?.add(b) }
                }

        val key = blox.entries.map { (_, bytes) ->
            val bArray = ByteArray(bytes.size, { bytes[it] })
            singleCharXOR(bArray).second
        }

        val output = inputBytes.mapIndexed { i, inputByte ->
            val compare = key[i.rem(ksize)]
            inputByte.xor(compare).toChar()
        }.joinToString("")

        Pair(output, engScore(output))
    }
    .sortedByDescending { it.second }
    .first().first

    println(answer.contains("I'm back and I'm ringin' the bell"))
}

fun chal7() {
    val inp = File("set1chal7.txt").readText().toByteArray("base64")
    val key = "YELLOW SUBMARINE".toByteArray("text")

    val secret = SecretKeySpec(key, "AES")
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, secret)

    println(String(cipher.doFinal(inp)).contains("I'm back and I'm ringin' the bell"))
}

fun chal8() {
    val texts =
        File("set1chal8.txt")
        .readText()
        .split("\n")
        .map { it.toByteArray("hex") }

    var ans = -1
    texts.forEachIndexed { i, txt ->
        val blox =
            txt
            .withIndex()
            .groupBy { it.index / 16 }
            .map { it.value.map{ it.value } }


        blox.forEachIndexed { j,outerBlock ->
            blox.forEachIndexed { k, innerBlock ->
                if(outerBlock == innerBlock && j != k && ans != i) ans = i
            }
        }
    }
    println(ans)
}

fun main(args: Array<String>){
    chal1()
    chal2()
    chal3()
    chal4()
    chal5()
    testHammingDistance()
    chal6()
    chal7()
    chal8()
}