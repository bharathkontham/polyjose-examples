// The operation log of PLAYGROUND.md ("Log", "Secrets"): one line per step of every tap,
//
//   LOG <tap>.<step> <event> key=value …
//
// kept for the Log tab and mirrored to logcat as `Log.i("POLYJOSE", line)`. The secrets rule is
// kept by construction:
// - the logger takes typed fields only: identifiers ([Field]), numbers and booleans, never free
//   text;
// - every JSON value is a [PublicJson], which only [publicOnly] makes: any object with a private
//   or symmetric member is replaced by "[withheld]";
// - an error is an [ErrorCode], which only [ErrorCode.of] makes: the `PolyjoseException`
//   subclass's simple name, or the throwable's class name, never its message.
package dev.polyjose.examples.playground

import android.os.SystemClock
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

/** The members of a private or symmetric JWK (RFC 7518 §6.2.2, §6.3.2, §6.4.1; RFC 8037 §2). */
internal val SECRET_MEMBERS = setOf("d", "p", "q", "dp", "dq", "qi", "oth", "k")

/** JSON text that has passed [publicOnly]: the only JSON a log line, or the screen, takes. */
class PublicJson private constructor(val text: String) {
    override fun toString() = text

    companion object {
        internal fun gated(text: String) = PublicJson(text)
    }
}

/**
 * The public-only gate: [json] with every object that holds a private or symmetric member
 * replaced by the string "[withheld]". Text that isn't JSON is withheld whole.
 */
fun publicOnly(json: String): PublicJson {
    fun gate(v: Any?): Any? = when (v) {
        is JSONObject -> if (v.keys().asSequence().any { it in SECRET_MEMBERS }) "[withheld]" else JSONObject().also { out ->
            for (name in v.keys()) out.put(name, gate(v.get(name)))
        }
        is JSONArray -> JSONArray().also { out -> for (i in 0 until v.length()) out.put(gate(v.get(i))) }
        else -> v
    }
    val gated = try {
        when (val v = gate(JSONTokener(json).nextValue())) {
            is JSONObject, is JSONArray -> v.toString()
            else -> "\"[withheld]\""
        }
    } catch (_: Exception) {
        "\"[withheld]\""
    }
    return PublicJson.gated(gated)
}

/** An error as its code only (PLAYGROUND.md "Secrets"). */
class ErrorCode private constructor(val name: String) {
    override fun toString() = name

    companion object {
        /** The `PolyjoseException` subclass's simple name, or the throwable's class name. Never its message. */
        fun of(t: Throwable): ErrorCode = ErrorCode(t.javaClass.simpleName.ifEmpty { t.javaClass.name })
    }
}

/** A compact JWS or JWE: base64url parts and dots only, so it can't carry anything else. */
class Token private constructor(val text: String) {
    override fun toString() = text

    companion object {
        private val SHAPE = Regex("^[A-Za-z0-9_-]*(\\.[A-Za-z0-9_-]*)+$")
        fun of(text: String): Token = Token(if (SHAPE.matches(text)) text else "[not a compact token]")
    }
}

/**
 * One `key=value` field. Values are identifiers, numbers or booleans; any character outside
 * `[A-Za-z0-9._:+/=@-]` becomes `_`, so a value never holds a space, a quote or JSON.
 */
class Field private constructor(val key: String, val value: String) {
    companion object {
        private val UNSAFE = Regex("[^A-Za-z0-9._:+/=@-]")
        fun id(key: String, value: String) = Field(key, UNSAFE.replace(value, "_").ifEmpty { "-" })
        fun num(key: String, value: Long) = Field(key, value.toString())
        fun bool(key: String, value: Boolean) = Field(key, value.toString())
        fun ms(nanos: Long) = Field("ms", (nanos / 1_000_000).toString())
    }
}

/** Monotonic time for the `ms` fields (shown, never checked). */
fun now(): Long = SystemClock.elapsedRealtimeNanos()

/** The whole log: the taps since the app started, newest last. Thread-safe. */
class PlaygroundLog(private val mirror: (String) -> Unit = { Log.i(TAG, it) }) {
    /** One tap: its number, its title (`Sign JWS ES256 · Keystore (TEE)`) and its lines. */
    class Entry(val tap: Int, val title: String) {
        val lines = ArrayList<String>()
    }

    private val entries = ArrayList<Entry>()
    private var nextTap = 1

    /** Called after every line, on the thread that logged it. */
    @Volatile var onChange: (() -> Unit)? = null

    /** Starts the next tap. */
    @Synchronized fun begin(title: String): Tap {
        val e = Entry(nextTap++, title)
        entries.add(e)
        return Tap(e)
    }

    /** Tap 0: the `device` line, once at start. */
    @Synchronized fun device(fields: List<Field>) {
        val e = Entry(0, "This device")
        entries.add(0, e)
        Tap(e).line("device", fields)
    }

    /** The log as text, newest tap first, each tap a `#n title` line and its lines. */
    @Synchronized fun text(maxChars: Int = Int.MAX_VALUE): String {
        val sb = StringBuilder()
        for (e in entries.asReversed()) {
            val block = buildString {
                append("#").append(e.tap).append(' ').append(e.title).append('\n')
                e.lines.forEach { append(it).append('\n') }
                append('\n')
            }
            if (sb.length + block.length > maxChars) {
                sb.append("(older entries omitted)\n")
                break
            }
            sb.append(block)
        }
        return sb.toString()
    }

    /**
     * The whole log, oldest tap first, with each `LOG <tap>.<step> + ` continuation joined back to
     * its line: the text the demo walk's secrets check searches.
     */
    @Synchronized fun joined(): String {
        val sb = StringBuilder()
        for (e in entries) {
            sb.append("#").append(e.tap).append(' ').append(e.title)
            for (line in e.lines) {
                val c = CONTINUATION.find(line)
                if (c != null) sb.append(line, c.range.last + 1, line.length) else sb.append('\n').append(line)
            }
            sb.append('\n')
        }
        return sb.toString()
    }

    @Synchronized fun clear() {
        val device = entries.firstOrNull { it.tap == 0 }
        entries.clear()
        device?.let { entries.add(it) }
        onChange?.invoke()
    }

    /** How many lines were mirrored to logcat since the app started (Clear doesn't reset it). */
    @get:Synchronized var mirrored = 0
        private set

    @Synchronized private fun add(e: Entry, line: String) {
        e.lines.add(line)
        mirror(line)
        mirrored++
    }

    /** The lines of one tap; each method is one event of PLAYGROUND.md's table. */
    inner class Tap internal constructor(private val entry: Entry) {
        private var step = 0
        val number: Int get() = entry.tap

        internal fun line(event: String, fields: List<Field>, rest: String? = null) {
            val body = buildString {
                append(event)
                fields.forEach { append(' ').append(it.key).append('=').append(it.value) }
                if (rest != null) append(' ').append(rest)
            }
            val s = ++step
            // Long lines are split every 800 characters; a continuation has `+` for the event.
            var i = 0
            while (i < body.length || i == 0) {
                val chunk = body.substring(i, minOf(body.length, i + CHUNK))
                add(entry, if (i == 0) "LOG ${entry.tap}.$s $chunk" else "LOG ${entry.tap}.$s + $chunk")
                i += CHUNK
            }
            onChange?.invoke()
        }

        fun input(fields: List<Field>) = line("input", fields)
        fun keyCreate(alias: String, reported: String, nanos: Long) = line("key-create", listOf(Field.id("alias", alias), Field.id("reported", reported), Field.ms(nanos)))
        fun keyOpen(alias: String, reported: String, nanos: Long) = line("key-open", listOf(Field.id("alias", alias), Field.id("reported", reported), Field.ms(nanos)))
        fun keyDelete(alias: String, nanos: Long) = line("key-delete", listOf(Field.id("alias", alias), Field.ms(nanos)))
        fun keySoftware(fields: List<Field>) = line("key-software", fields)
        fun jwk(jwk: PublicJson) = line("jwk", emptyList(), jwk.text)
        fun thumbprint(value: String) = line("thumbprint", listOf(Field.id("value", value)))
        /** `call <function> ms=…`: the function name is the first word. */
        fun call(function: String, nanos: Long) = line("call ${Field.id("fn", function).value}", listOf(Field.ms(nanos)))
        fun tamper(part: String, index: Int) = line("tamper", listOf(Field.id("part", part), Field.num("index", index.toLong())))
        fun header(header: PublicJson) = line("header", emptyList(), header.text)
        fun token(token: Token) = line("token", emptyList(), token.text)
        fun verify(alg: String, kid: String?, nanos: Long) = line(
            "verify ok",
            listOfNotNull(Field.id("alg", alg), kid?.let { Field.id("kid", it) }, Field.ms(nanos)),
        )
        fun claims(claims: PublicJson) = line("claims", emptyList(), claims.text)
        fun decrypt(alg: String, enc: String, equal: Boolean, nanos: Long) = line(
            "decrypt ok",
            listOf(Field.id("alg", alg), Field.id("enc", enc), Field.id("plaintext", if (equal) "equal" else "differs"), Field.ms(nanos)),
        )
        fun error(code: ErrorCode, nanos: Long) = line("error", listOf(Field.id("code", code.name), Field.ms(nanos)))
        fun note(id: String) = line("note", listOf(Field.id("id", id)))
        /** The time-bound prompt's outcome; [result] is the framework's error number, never its text. */
        fun authenticate(ok: Boolean, nanos: Long, result: Int?) = line(
            if (ok) "authenticate ok" else "authenticate failed",
            listOfNotNull(result?.let { Field.num("result", it.toLong()) }, Field.ms(nanos)),
        )
    }

    companion object {
        const val TAG = "POLYJOSE"
        const val CHUNK = 800
        private val CONTINUATION = Regex("^LOG [0-9]+\\.[0-9]+ \\+ ")
    }
}
