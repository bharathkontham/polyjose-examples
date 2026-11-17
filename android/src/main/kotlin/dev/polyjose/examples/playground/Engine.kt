// What every playground button does, as one synchronous function per tap: the Sign and Encrypt
// operations, the failure actions and the Keys tab's actions. The buttons and the demo walk call
// the same functions, always on the playground's one background executor (Playground.kt): a key
// with user authentication blocks the calling thread while its prompt is up.
//
// Platform keys go through the example files PlatformKeysKeystore.kt and PlatformKeysStrongBox.kt,
// software keys through SignVerifyJws.kt, SignVerifyJwt.kt and EncryptDecrypt.kt. Every verify and
// decrypt passes an explicit allow-list: the chosen algorithm (RFC 8725 §3.1), never one read from
// the token; `none` is never offered (RFC 8725 §3.2).
package dev.polyjose.examples.playground

import dev.polyjose.AndroidKeystoreKey
import dev.polyjose.JweEncryptOptions
import dev.polyjose.JweRecipient
import dev.polyjose.JwtVerifyOptions
import dev.polyjose.PlatformKeyAuthorizer
import dev.polyjose.decodeProtectedHeaderUnverified
import dev.polyjose.examples.RFC7515_A2_RSA_PRIVATE_JWK
import dev.polyjose.examples.createKeystoreKey
import dev.polyjose.examples.createStrongBoxKey
import dev.polyjose.examples.decrypt
import dev.polyjose.examples.deleteKeystoreKey
import dev.polyjose.examples.issueToken
import dev.polyjose.examples.keystoreDecrypt
import dev.polyjose.examples.keystoreKeyLevel
import dev.polyjose.examples.keystoreSignCompact
import dev.polyjose.examples.keystoreSignJwt
import dev.polyjose.examples.openKeystoreKey
import dev.polyjose.examples.signCompact
import dev.polyjose.examples.strongBoxDecrypt
import dev.polyjose.examples.strongBoxKeyLevel
import dev.polyjose.examples.strongBoxSignCompact
import dev.polyjose.examples.strongBoxSignJwt
import dev.polyjose.examples.thumbprint
import dev.polyjose.examples.validateToken
import dev.polyjose.examples.verifyCompact
import dev.polyjose.jweEncryptCompact
import dev.polyjose.jwkGenerateEc
import dev.polyjose.jwkGenerateForAlg
import dev.polyjose.jwkGenerateOct
import dev.polyjose.jwkGenerateOkp
import dev.polyjose.jwkToPublic
import dev.polyjose.jwtVerify
import org.json.JSONObject

/** The demo payloads (PLAYGROUND.md `option.payload`): fixed, never free text. */
object Payloads {
    const val JWS_TEXT = "polyjose example payload"
    val JWS: ByteArray get() = JWS_TEXT.toByteArray(Charsets.UTF_8)
    const val ISSUER = "https://issuer.example"
    const val AUDIENCE = "https://api.example"

    /** `iss`, `aud`, `sub` and `exp` (RFC 7519 §4.1), `exp` five minutes from now unless given. */
    fun claims(exp: Long = System.currentTimeMillis() / 1000 + 300): String =
        JSONObject().put("iss", ISSUER).put("aud", AUDIENCE).put("sub", "user-123").put("exp", exp).toString()
}

enum class Kind { Sign, Encrypt }

/** The buttons of the Sign and Encrypt tabs. [id] is the `op` value of the log. */
enum class Action(val id: String, val kind: Kind, val label: String) {
    JwsSign("jws-sign", Kind.Sign, "Sign"),
    JwsVerify("jws-verify", Kind.Sign, "Verify"),
    JwsSignVerify("jws-sign-verify", Kind.Sign, "Sign and verify"),
    JwtSign("jwt-sign", Kind.Sign, "Sign"),
    JwtVerify("jwt-verify", Kind.Sign, "Verify"),
    JwtSignVerify("jwt-sign-verify", Kind.Sign, "Sign and verify"),
    JweEncrypt("jwe-encrypt", Kind.Encrypt, "Encrypt"),
    JweDecrypt("jwe-decrypt", Kind.Encrypt, "Decrypt"),
    JweRoundTrip("jwe-round-trip", Kind.Encrypt, "Round trip");

    val signs: Boolean get() = this == JwsSign || this == JwsSignVerify || this == JwtSign || this == JwtSignVerify || this == JweEncrypt || this == JweRoundTrip
    val verifies: Boolean get() = this != JwsSign && this != JwtSign && this != JweEncrypt
    val jwt: Boolean get() = this == JwtSign || this == JwtVerify || this == JwtSignVerify
}

/** The failure actions of PLAYGROUND.md, with the code each one ends with. */
enum class Failure(val id: String, val kind: Kind, val label: String, val expected: String) {
    SignTamper("sign.tamper", Kind.Sign, "Tamper with the payload", "InvalidSignature"),
    SignOtherAlg("sign.other-alg", Kind.Sign, "Allow only another algorithm", "AlgorithmNotAllowed"),
    SignWrongKey("sign.wrong-key", Kind.Sign, "Verify with the wrong key", "InvalidSignature"),
    SignExpired("sign.expired", Kind.Sign, "Expired JWT", "TokenExpired"),
    SignDeletedKey("sign.deleted-key", Kind.Sign, "Use a deleted key", "KeyNotFound"),
    EncryptTamper("encrypt.tamper", Kind.Encrypt, "Tamper with the ciphertext", "DecryptionFailed"),
    EncryptOtherAlg("encrypt.other-alg", Kind.Encrypt, "Allow only another alg", "AlgorithmNotAllowed"),
    EncryptWrongKey("encrypt.wrong-key", Kind.Encrypt, "Decrypt with the wrong key", "DecryptionFailed"),
    EncryptDeletedKey("encrypt.deleted-key", Kind.Encrypt, "Use a deleted key", "KeyNotFound");

    val explanation: String get() = "failure.$id"

    /** Why this action is disabled for [sel], or null when it can run. */
    fun reason(sel: Selection): Reason? = when {
        (this == SignDeletedKey || this == EncryptDeletedKey) && sel.store == Store.Software -> Matrix.SOFTWARE_NOT_STORED
        (this == SignWrongKey || this == EncryptWrongKey) && sel.store == Store.Software &&
            (Matrix.isRsaSign(sel.alg) || sel.alg == "RSA-OAEP-256") -> Matrix.ONE_SOFTWARE_RSA_KEY
        else -> null
    }
}

/** Which key a tap uses: a new one, or one from the Keys tab. */
sealed class KeyChoice {
    object New : KeyChoice()
    data class Platform(val alias: String) : KeyChoice()
    data class Software(val id: Int) : KeyChoice()
}

/** Everything the pickers of a tab hold. */
data class Selection(
    val kind: Kind,
    val jwt: Boolean = false,
    val store: Store = Store.Software,
    val mode: StrongBoxMode = StrongBoxMode.Preferred,
    val alg: String = if (kind == Kind.Sign) "ES256" else "ECDH-ES+A256KW",
    val enc: String = "A256GCM",
    val crv: String = "P-256",
    val rsaSize: Int = 2048,
    val auth: Auth = Auth.None,
    val key: KeyChoice = KeyChoice.New,
) {
    fun cell(device: DeviceInfo): Cell =
        Matrix.cell(store, mode, alg, if (Matrix.isEcdh(alg)) crv else null, rsaSize, auth, device)

    val storeLabel: String get() = when (store) {
        Store.Software -> "Software"
        Store.Keystore -> "Keystore (TEE)"
        Store.StrongBox -> "StrongBox ${mode.name}"
    }
}

/**
 * A software key in app memory for this session only (PLAYGROUND.md "Secrets"): its JWK is passed
 * to polyjose and nowhere else; [toString] shows no key material.
 */
class SoftwareKey internal constructor(val id: Int, val alg: String, val crv: String?, private val jwk: String, val testKey: Boolean) {
    private val json = JSONObject(jwk)
    val kty: String = json.optString("kty")
    val kid: String? = json.optString("kid").ifEmpty { null }
    val isOct: Boolean get() = kty == "oct"

    /** For oct keys: the length in bits, from the key's size (the value is never shown). */
    val bits: Int? = if (isOct) json.optString("k").length * 6 / 8 * 8 else null

    internal fun secret(): String = jwk

    /** The public JWK, or null for an oct key (it has none). */
    fun publicJwk(): String? = if (isOct) null else jwkToPublic(jwk)

    override fun toString() = "SoftwareKey(id=$id, alg=$alg, kty=$kty)"
}

/** The key a tap ended up with. */
sealed class KeyHandle {
    class Soft(val key: SoftwareKey) : KeyHandle()
    class Platform(val alias: String, val algorithm: String, val key: AndroidKeystoreKey, val strongBoxFile: Boolean) : KeyHandle()

    /** "Key lives in": the platform's report, or app memory. */
    val lives: String get() = when (this) {
        is Soft -> "app memory (software)"
        is Platform -> key.securityLevel.name
    }
}

/** What a tap showed: the result card's content. Never a key's private part or an error message. */
class Result(val title: String) {
    var token: Token? = null
    var header: PublicJson? = null
    var claims: PublicJson? = null
    val outcome = ArrayList<String>()
    var code: ErrorCode? = null
    var keyLives: String? = null
    val steps = ArrayList<Pair<String, Long>>()
    val notes = ArrayList<String>()

    /** A platform key's alias, and whether a key is under it after the tap (for the walk). */
    var alias: String? = null
    var aliasLeft: Boolean? = null
    var level: AndroidKeystoreKey.SecurityLevel? = null
    var decryptedEqual: Boolean? = null
    var verified: Boolean = false
}

/** One tap: a button with the pickers' selection, a failure action, or Run anyway. */
class Request(val sel: Selection, val action: Action? = null, val failure: Failure? = null, val anyway: Boolean = false)

/** Shows the per-use prompt: the activity's `BiometricPromptAuthorizer`. */
fun interface AuthorizerFactory {
    fun authorizer(deviceCredential: Boolean, subtitle: String): PlatformKeyAuthorizer
}

class Engine(private val log: PlaygroundLog, private val authorizers: AuthorizerFactory) {
    private val software = ArrayList<SoftwareKey>()
    private var nextSoftwareId = 1

    /** The last token of each tab, for Verify and Decrypt on their own. */
    private class Last(val token: String, val alg: String, val enc: String, val jwt: Boolean, val key: KeyHandle)
    private var lastSign: Last? = null
    private var lastEncrypt: Last? = null

    @Synchronized fun softwareKeys(): List<SoftwareKey> = software.toList()

    /** Runs [req] and returns what its result card shows. Call it on the playground executor. */
    fun perform(req: Request, device: DeviceInfo): Result {
        val sel = req.sel
        val op = req.action ?: when (sel.kind) {
            Kind.Sign -> if (sel.jwt || req.failure == Failure.SignExpired) Action.JwtSignVerify else Action.JwsSignVerify
            Kind.Encrypt -> Action.JweRoundTrip
        }
        val title = buildString {
            append(if (req.failure != null) "Failure ${req.failure.id}" else op.label)
            append(if (sel.kind == Kind.Sign) (if (op.jwt) " JWT " else " JWS ") else " JWE ")
            append(sel.alg)
            if (sel.kind == Kind.Encrypt) append(" ").append(sel.enc)
            append(" · ").append(sel.storeLabel)
            if (req.anyway) append(" (Run anyway)")
        }
        val r = Result(title)
        val tap = log.begin(title)
        tap.input(inputFields(op, req, device))
        var stepStart = now()
        try {
            if (req.failure != null) {
                failure(tap, r, req.failure, sel, op, device) { stepStart = now() }
            } else {
                operation(tap, r, op, sel, device) { stepStart = now() }
            }
        } catch (t: Throwable) {
            val code = ErrorCode.of(t)
            val ms = now() - stepStart
            tap.error(code, ms)
            r.code = code
            r.steps.add("error" to ms / 1_000_000)
        }
        r.alias?.let { if (r.aliasLeft == null) r.aliasLeft = PlaygroundKeys.exists(it) }
        r.notes.forEach { tap.note(it) }
        return r
    }

    private fun inputFields(op: Action, req: Request, device: DeviceInfo): List<Field> {
        val sel = req.sel
        val f = ArrayList<Field>()
        f += Field.id("op", op.id)
        f += Field.id("store", sel.store.id)
        f += Field.id("alg", sel.alg)
        if (sel.kind == Kind.Encrypt) f += Field.id("enc", sel.enc)
        if (sel.kind == Kind.Encrypt && Matrix.isEcdh(sel.alg)) f += Field.id("crv", sel.crv)
        if (Matrix.isRsaSign(sel.alg) || sel.alg == "RSA-OAEP-256") {
            if (sel.store != Store.Software) f += Field.num("size", sel.rsaSize.toLong())
        }
        if (sel.store == Store.StrongBox) f += Field.id("strongbox", sel.mode.id)
        if (sel.store != Store.Software) {
            f += Field.id("auth", sel.auth.id)
            when (val a = sel.auth) {
                is Auth.TimeBound -> {
                    f += Field.num("seconds", a.seconds.toLong())
                    f += Field.bool("device-credential", Matrix.deviceCredential(a, device))
                }
                is Auth.PerUse -> f += Field.bool("device-credential", Matrix.deviceCredential(a, device))
                Auth.None -> Unit
            }
        }
        if (sel.kind == Kind.Sign) f += Field.id("payload", if (op.jwt) "jwt-claims" else "jws-text")
        when (val k = sel.key) {
            is KeyChoice.Platform -> f += Field.id("key", k.alias)
            is KeyChoice.Software -> f += Field.num("key", k.id.toLong())
            KeyChoice.New -> Unit
        }
        req.failure?.let { f += Field.id("failure", it.id) }
        if (req.anyway) f += Field.bool("anyway", true)
        return f
    }

    // --- operations -------------------------------------------------------------------------------

    private fun operation(tap: PlaygroundLog.Tap, r: Result, op: Action, sel: Selection, device: DeviceInfo, mark: () -> Unit) {
        if (!op.signs) {
            // Verify or Decrypt on its own: the tab's last token and key.
            val last = (if (sel.kind == Kind.Sign) lastSign else lastEncrypt)
            if (last == null) {
                r.outcome += "Nothing to ${op.label.lowercase()} yet: tap ${if (sel.kind == Kind.Sign) "Sign" else "Encrypt"} first."
                return
            }
            r.keyLives = last.key.lives
            r.token = Token.of(last.token)
            if (sel.kind == Kind.Sign) verify(tap, r, last.token, last.key, last.alg, last.jwt, listOf(last.alg), mark)
            else decryptStep(tap, r, last.token, last.key, last.alg, last.enc, listOf(last.alg), mark)
            return
        }
        mark()
        val key = obtainKey(tap, r, sel, device)
        r.keyLives = key.lives
        if (sel.kind == Kind.Sign) {
            mark()
            val token = signStep(tap, r, key, sel.alg, op.jwt, Payloads.claims())
            lastSign = Last(token, sel.alg, sel.enc, op.jwt, key)
            if (op.verifies) verify(tap, r, token, key, sel.alg, op.jwt, listOf(sel.alg), mark)
        } else {
            mark()
            val token = encryptStep(tap, r, recipientKey(key), sel.alg, sel.enc)
            lastEncrypt = Last(token, sel.alg, sel.enc, false, key)
            if (op.verifies) decryptStep(tap, r, token, key, sel.alg, sel.enc, listOf(sel.alg), mark)
        }
    }

    private fun failure(tap: PlaygroundLog.Tap, r: Result, f: Failure, sel: Selection, op: Action, device: DeviceInfo, mark: () -> Unit) {
        f.reason(sel)?.let { reason ->
            r.outcome += "Disabled: ${reason.line}."
            r.notes += reason.id
            return
        }
        r.notes += f.explanation
        mark()
        if (f == Failure.SignDeletedKey || f == Failure.EncryptDeletedKey) {
            val key = obtainKey(tap, r, sel.copy(key = KeyChoice.New), device) as KeyHandle.Platform
            mark()
            val t0 = now()
            deleteKeystoreKey(key.alias)
            tap.keyDelete(key.alias, now() - t0)
            r.steps.add("delete" to (now() - t0) / 1_000_000)
            mark()
            val t1 = now()
            val opened = openKeystoreKey(key.alias, key.algorithm)
            tap.keyOpen(key.alias, opened.securityLevel.name, now() - t1)
            r.outcome += "The deleted key opened again: unexpected."
            return
        }
        val key = obtainKey(tap, r, sel, device)
        r.keyLives = key.lives
        mark()
        if (f.kind == Kind.Sign) {
            val jwt = op.jwt || f == Failure.SignExpired
            val exp = if (f == Failure.SignExpired) System.currentTimeMillis() / 1000 - 3600 else System.currentTimeMillis() / 1000 + 300
            var token = signStep(tap, r, key, sel.alg, jwt, Payloads.claims(exp))
            mark()
            when (f) {
                Failure.SignTamper -> {
                    val (changed, index) = tamper(token, 1)
                    tap.tamper("payload", index)
                    token = changed
                    tap.token(Token.of(token))
                    r.token = Token.of(token)
                    verify(tap, r, token, key, sel.alg, jwt, listOf(sel.alg), mark)
                }
                Failure.SignOtherAlg -> verify(tap, r, token, key, sel.alg, jwt, listOf(Matrix.otherSignAlg(sel.alg)), mark)
                Failure.SignWrongKey -> verify(tap, r, token, KeyHandle.Soft(otherKey(tap, r, sel, key)), sel.alg, jwt, listOf(sel.alg), mark)
                Failure.SignExpired -> verify(tap, r, token, key, sel.alg, true, listOf(sel.alg), mark, leewayZero = true)
                else -> Unit
            }
        } else {
            val token = when (f) {
                Failure.EncryptWrongKey -> encryptStep(tap, r, recipientKey(KeyHandle.Soft(otherKey(tap, r, sel, key))), sel.alg, sel.enc)
                else -> encryptStep(tap, r, recipientKey(key), sel.alg, sel.enc)
            }
            mark()
            when (f) {
                Failure.EncryptTamper -> {
                    val (changed, index) = tamper(token, 3)
                    tap.tamper("ciphertext", index)
                    tap.token(Token.of(changed))
                    r.token = Token.of(changed)
                    decryptStep(tap, r, changed, key, sel.alg, sel.enc, listOf(sel.alg), mark)
                }
                Failure.EncryptOtherAlg -> decryptStep(tap, r, token, key, sel.alg, sel.enc, listOf(Matrix.otherJweAlg(sel.alg)), mark)
                Failure.EncryptWrongKey -> decryptStep(tap, r, token, key, sel.alg, sel.enc, listOf(sel.alg), mark)
                else -> Unit
            }
        }
    }

    /** Changes one character in the middle of part [index] of a compact token (`A`↔`B`). */
    private fun tamper(token: String, index: Int): Pair<String, Int> {
        val parts = token.split(".").toMutableList()
        val p = parts[index]
        val i = p.length / 2
        parts[index] = p.substring(0, i) + (if (p[i] == 'A') 'B' else 'A') + p.substring(i + 1)
        return parts.joinToString(".") to i
    }

    // --- keys -------------------------------------------------------------------------------------

    /** The key of [sel]: a new one in its store, or the chosen one from the Keys tab. */
    private fun obtainKey(tap: PlaygroundLog.Tap, r: Result, sel: Selection, device: DeviceInfo): KeyHandle = when (val k = sel.key) {
        is KeyChoice.Software -> KeyHandle.Soft(synchronized(this) { software.first { it.id == k.id } }).also { logSoftware(tap, it.key, r) }
        is KeyChoice.Platform -> openPlatform(tap, r, k.alias, device)
        KeyChoice.New -> if (sel.store == Store.Software) KeyHandle.Soft(newSoftwareKey(tap, r, sel)) else createPlatform(tap, r, sel, device)
    }

    private fun newSoftwareKey(tap: PlaygroundLog.Tap, r: Result, sel: Selection): SoftwareKey {
        val alg = sel.alg
        val (jwk, test) = when {
            Matrix.isRsaSign(alg) || alg == "RSA-OAEP-256" -> RFC7515_A2_RSA_PRIVATE_JWK to true
            sel.kind == Kind.Sign -> jwkGenerateForAlg(alg) to false // HS*, ES*, EdDSA (RFC 7518 §6, RFC 8037 §2)
            Matrix.isEcdh(alg) -> (if (sel.crv == "X25519") jwkGenerateOkp("X25519") else jwkGenerateEc(sel.crv)) to false
            else -> jwkGenerateOct(Matrix.octBytes(alg, sel.enc).toUInt()) to false // RFC 7518 §6.4
        }
        val key = synchronized(this) {
            SoftwareKey(nextSoftwareId++, alg, if (Matrix.isEcdh(alg)) sel.crv else null, jwk, test).also {
                software.add(it)
                if (software.size > 50) software.removeAt(0)
            }
        }
        logSoftware(tap, key, r)
        return key
    }

    private fun logSoftware(tap: PlaygroundLog.Tap, key: SoftwareKey, r: Result) {
        val f = arrayListOf(Field.id("kty", key.kty), Field.id("alg", key.alg), Field.id("kid", key.kid ?: "-"))
        key.bits?.let { f += Field.num("bits", it.toLong()) }
        if (key.testKey) {
            f += Field.bool("test-key", true)
            if ("key.test-rsa" !in r.notes) r.notes += "key.test-rsa"
        }
        tap.keySoftware(f)
    }

    /**
     * The other key of a wrong-key action: a new software key of the same algorithm and curve or
     * size. For a platform RSA key it is the RFC 7515 A.2 test key (polyjose 0.4.0 can't generate
     * RSA keys); a software RSA key has no other key, so that action is disabled.
     */
    private fun otherKey(tap: PlaygroundLog.Tap, r: Result, sel: Selection, mine: KeyHandle): SoftwareKey {
        val crv = when {
            mine is KeyHandle.Soft -> mine.key.crv ?: sel.crv
            mine is KeyHandle.Platform && mine.algorithm == "ECDH-ES" -> ecdhCurve(mine.key.publicJwk()) ?: sel.crv
            else -> sel.crv
        }
        return newSoftwareKey(tap, r, sel.copy(crv = crv))
    }

    private fun ecdhCurve(publicJwk: String): String? = JSONObject(publicJwk).optString("crv").ifEmpty { null }

    /** The platform algorithm name and key size [sel] asks `AndroidKeystoreKey` for (Run anyway passes the row as it is). */
    private fun platformSpec(sel: Selection): KeySpec =
        Matrix.keySpec(sel.alg, if (Matrix.isEcdh(sel.alg)) sel.crv else null, sel.rsaSize) ?: when {
            // X25519 isn't a Keystore curve: ask for ECDH-ES on Curve25519's size, which the library refuses.
            Matrix.isEcdh(sel.alg) -> KeySpec("ECDH-ES", 255)
            else -> KeySpec(sel.alg, null) // HS*, EdDSA, AES key wrap, dir
        }

    private fun createPlatform(tap: PlaygroundLog.Tap, r: Result, sel: Selection, device: DeviceInfo): KeyHandle.Platform {
        val spec = platformSpec(sel)
        val alias = PlaygroundKeys.nextAlias(spec.algorithm)
        val dc = Matrix.deviceCredential(sel.auth, device)
        val auth = when (val a = sel.auth) {
            Auth.None -> null
            is Auth.TimeBound -> AndroidKeystoreKey.UserAuthentication(a.seconds, dc)
            is Auth.PerUse -> AndroidKeystoreKey.UserAuthentication(0, dc)
        }
        val authorizer = if (sel.auth is Auth.PerUse) authorizers.authorizer(dc, "${sel.alg} · ${sel.storeLabel}") else null
        val size = if (spec.algorithm.startsWith("ES")) null else spec.keySize
        r.alias = alias
        val t0 = now()
        val key = try {
            if (sel.store == Store.Keystore) {
                createKeystoreKey(alias, spec.algorithm, size, auth, authorizer)
            } else {
                createStrongBoxKey(alias, spec.algorithm, if (sel.mode == StrongBoxMode.Required) AndroidKeystoreKey.StrongBox.Required else AndroidKeystoreKey.StrongBox.Preferred, size, auth, authorizer)
            }
        } finally {
            r.aliasLeft = PlaygroundKeys.exists(alias)
        }
        val ms = now() - t0
        val level = if (sel.store == Store.Keystore) keystoreKeyLevel(key) else strongBoxKeyLevel(key)
        tap.keyCreate(alias, level.name, ms)
        r.steps.add("key-create" to ms / 1_000_000)
        r.level = level
        return KeyHandle.Platform(alias, spec.algorithm, key, sel.store == Store.StrongBox)
    }

    private fun openPlatform(tap: PlaygroundLog.Tap, r: Result, alias: String, device: DeviceInfo): KeyHandle.Platform {
        val algorithm = PlaygroundKeys.algorithmOf(alias)
        val info = PlaygroundKeys.info(alias)
        val authorizer = if (info?.perUse == true) authorizers.authorizer(info.deviceCredential && device.api >= Matrix.DEVICE_CREDENTIAL_API, "$algorithm · $alias") else null
        r.alias = alias
        val t0 = now()
        val key = openKeystoreKey(alias, algorithm, authorizer)
        val ms = now() - t0
        tap.keyOpen(alias, key.securityLevel.name, ms)
        r.steps.add("key-open" to ms / 1_000_000)
        r.level = key.securityLevel
        return KeyHandle.Platform(alias, algorithm, key, key.securityLevel == AndroidKeystoreKey.SecurityLevel.StrongBox)
    }

    /** The key a JWE is encrypted to: the public JWK, or the shared oct key itself (RFC 7518 §4.4, §4.5, §4.7). */
    private fun recipientKey(key: KeyHandle): String = when (key) {
        is KeyHandle.Soft -> key.key.publicJwk() ?: key.key.secret()
        is KeyHandle.Platform -> key.key.publicJwk()
    }

    /** The key a signature is verified with: the public JWK, or the HMAC secret itself (RFC 7518 §3.2). */
    private fun verifyKey(key: KeyHandle): String = when (key) {
        is KeyHandle.Soft -> key.key.publicJwk() ?: key.key.secret()
        is KeyHandle.Platform -> key.key.publicJwk()
    }

    // --- steps ------------------------------------------------------------------------------------

    private fun showToken(tap: PlaygroundLog.Tap, r: Result, token: String) {
        val t0 = now()
        val header = publicOnly(decodeProtectedHeaderUnverified(token))
        tap.call("decodeProtectedHeaderUnverified", now() - t0)
        tap.header(header)
        tap.token(Token.of(token))
        r.header = header
        r.token = Token.of(token)
    }

    /** Signs the demo payload (RFC 7515 §5.1) or the demo claims (RFC 7519 §7.1). */
    private fun signStep(tap: PlaygroundLog.Tap, r: Result, key: KeyHandle, alg: String, jwt: Boolean, claims: String): String {
        val t0 = now()
        val (token, fn) = when (key) {
            is KeyHandle.Soft ->
                if (jwt) issueToken(claims, key.key.secret(), alg) to "jwtSign" else signCompact(Payloads.JWS, key.key.secret(), alg) to "jwsSignCompact"
            is KeyHandle.Platform -> when {
                jwt && key.strongBoxFile -> strongBoxSignJwt(claims, key.key, alg) to "jwtSignWithPlatformKey"
                jwt -> keystoreSignJwt(claims, key.key, alg) to "jwtSignWithPlatformKey"
                key.strongBoxFile -> strongBoxSignCompact(Payloads.JWS, key.key, alg) to "jwsSignCompactWithPlatformKey"
                else -> keystoreSignCompact(Payloads.JWS, key.key, alg) to "jwsSignCompactWithPlatformKey"
            }
        }
        val ms = now() - t0
        tap.call(fn, ms)
        r.steps.add("sign" to ms / 1_000_000)
        showToken(tap, r, token)
        return token
    }

    /** Verifies in software with [key]'s public JWK and the allow-list [allowed] (RFC 7515 §5.2, RFC 7519 §7.2). */
    private fun verify(tap: PlaygroundLog.Tap, r: Result, token: String, key: KeyHandle, alg: String, jwt: Boolean, allowed: List<String>, mark: () -> Unit, leewayZero: Boolean = false) {
        mark()
        val vk = verifyKey(key)
        val t0 = now()
        if (jwt) {
            val verified = if (leewayZero) {
                jwtVerify(token, vk, JwtVerifyOptions(allowedAlgs = allowed, issuers = listOf(Payloads.ISSUER), audiences = listOf(Payloads.AUDIENCE), leeway = 0u))
            } else if (allowed == listOf(alg)) {
                validateToken(token, vk, alg, Payloads.ISSUER, Payloads.AUDIENCE)
            } else {
                jwtVerify(token, vk, JwtVerifyOptions(allowedAlgs = allowed, issuers = listOf(Payloads.ISSUER), audiences = listOf(Payloads.AUDIENCE)))
            }
            val ms = now() - t0
            tap.call("jwtVerify", ms)
            tap.verify(verified.alg, verified.kid, ms)
            val claims = publicOnly(verified.claims)
            tap.claims(claims)
            r.claims = claims
            r.outcome += "Verified: alg ${verified.alg}${verified.kid?.let { ", kid $it" } ?: ""}; claims below."
            r.steps.add("verify" to ms / 1_000_000)
        } else {
            val verified = verifyCompact(token, vk, allowed.single())
            val ms = now() - t0
            tap.call("jwsVerifyCompact", ms)
            val kid = JSONObject(verified.protectedHeader).optString("kid").ifEmpty { null }
            tap.verify(verified.alg, kid, ms)
            val same = verified.payload.contentEquals(Payloads.JWS)
            r.outcome += "Verified: alg ${verified.alg}${kid?.let { ", kid $it" } ?: ""}; payload ${if (same) "is the demo payload" else "differs"}."
            r.steps.add("verify" to ms / 1_000_000)
        }
        r.verified = true
    }

    /** Encrypts the demo payload in software to [recipient] (RFC 7516 §5.1). */
    private fun encryptStep(tap: PlaygroundLog.Tap, r: Result, recipient: String, alg: String, enc: String): String {
        val t0 = now()
        val token = jweEncryptCompact(Payloads.JWS, JweEncryptOptions(enc = enc, recipients = listOf(JweRecipient(alg = alg, key = recipient))))
        val ms = now() - t0
        tap.call("jweEncryptCompact", ms)
        r.steps.add("encrypt" to ms / 1_000_000)
        showToken(tap, r, token)
        return token
    }

    /** Decrypts with [key] in its store and the allow-lists [allowedAlgs] and `[enc]` (RFC 7516 §5.2). */
    private fun decryptStep(tap: PlaygroundLog.Tap, r: Result, token: String, key: KeyHandle, alg: String, enc: String, allowedAlgs: List<String>, mark: () -> Unit) {
        mark()
        val t0 = now()
        val (decrypted, fn) = when (key) {
            is KeyHandle.Soft -> decrypt(token, key.key.secret(), allowedAlgs, listOf(enc)) to "jweDecryptCompact"
            is KeyHandle.Platform ->
                (if (key.strongBoxFile) strongBoxDecrypt(token, key.key, allowedAlgs, listOf(enc)) else keystoreDecrypt(token, key.key, allowedAlgs, listOf(enc))) to
                    "jweDecryptCompactWithPlatformKey"
        }
        val ms = now() - t0
        val equal = decrypted.plaintext.contentEquals(Payloads.JWS)
        decrypted.plaintext.fill(0)
        tap.call(fn, ms)
        tap.decrypt(alg, enc, equal, ms)
        r.decryptedEqual = equal
        r.outcome += if (equal) "Decrypted: the plaintext is the demo payload, \"${Payloads.JWS_TEXT}\"." else "Decrypted, but the plaintext differs from the input."
        r.steps.add("decrypt" to ms / 1_000_000)
    }

    // --- the Keys tab -----------------------------------------------------------------------------

    /** Keys tab, **Create key**: a new key of [sel] (no user authentication). */
    fun createKey(sel: Selection, device: DeviceInfo): Result {
        val r = Result("Create key ${sel.alg} · ${sel.storeLabel}")
        val tap = log.begin(r.title)
        tap.input(listOfNotNull(Field.id("op", "key-create"), Field.id("store", sel.store.id), Field.id("alg", sel.alg), if (sel.store == Store.StrongBox) Field.id("strongbox", sel.mode.id) else null))
        val t0 = now()
        try {
            val key = createPlatform(tap, r, sel.copy(auth = Auth.None, key = KeyChoice.New), device)
            r.keyLives = key.lives
            r.outcome += "Created ${key.alias}."
        } catch (t: Throwable) {
            r.code = ErrorCode.of(t)
            tap.error(r.code!!, now() - t0)
        }
        return r
    }

    /** What **Open again** shows: the public JWK and its RFC 7638 thumbprint. */
    class Opened(val alias: String, val level: String?, val jwk: PublicJson?, val thumbprint: String?, val code: ErrorCode?)

    /** Keys tab, **Open again**: opens the key by its alias and shows its public JWK and thumbprint. */
    fun openAgain(alias: String, device: DeviceInfo): Opened {
        val tap = log.begin("Open again $alias")
        tap.input(listOf(Field.id("op", "key-open"), Field.id("store", "keystore"), Field.id("alg", PlaygroundKeys.algorithmOf(alias)), Field.id("key", alias)))
        val t0 = now()
        return try {
            val r = Result("open")
            val key = openPlatform(tap, r, alias, device)
            val jwk = publicOnly(key.key.publicJwk())
            tap.jwk(jwk)
            val t1 = now()
            val tp = thumbprint(key.key.publicJwk())
            tap.call("jwkThumbprint", now() - t1)
            tap.thumbprint(tp)
            Opened(alias, key.lives, jwk, tp, null)
        } catch (t: Throwable) {
            val code = ErrorCode.of(t)
            tap.error(code, now() - t0)
            Opened(alias, null, null, null, code)
        }
    }

    /** The public JWK and thumbprint of a software key (none for an oct key: RFC 7638 §7). */
    fun showSoftware(id: Int): Opened? {
        val key = synchronized(this) { software.firstOrNull { it.id == id } } ?: return null
        val pub = key.publicJwk() ?: return Opened("software ${key.id}", "app memory (software)", null, null, null)
        val tap = log.begin("Show software key ${key.id} ${key.alg}")
        tap.input(listOf(Field.id("op", "key-open"), Field.id("store", "software"), Field.id("alg", key.alg), Field.num("key", key.id.toLong())))
        val jwk = publicOnly(pub)
        tap.jwk(jwk)
        val t0 = now()
        val tp = thumbprint(pub)
        tap.call("jwkThumbprint", now() - t0)
        tap.thumbprint(tp)
        return Opened("software ${key.id}", "app memory (software)", jwk, tp, null)
    }

    /** Keys tab, **Delete**. */
    fun delete(alias: String): ErrorCode? {
        val tap = log.begin("Delete $alias")
        tap.input(listOf(Field.id("op", "key-delete"), Field.id("store", "keystore"), Field.id("alg", PlaygroundKeys.algorithmOf(alias)), Field.id("key", alias)))
        val t0 = now()
        return try {
            deleteKeystoreKey(alias)
            tap.keyDelete(alias, now() - t0)
            null
        } catch (t: Throwable) {
            ErrorCode.of(t).also { tap.error(it, now() - t0) }
        }
    }

    /** Keys tab, **Delete all playground keys**: every alias with the playground prefix, nothing else. */
    fun deleteAll(): Int {
        val tap = log.begin("Delete all playground keys")
        tap.input(listOf(Field.id("op", "key-delete-all"), Field.id("store", "keystore"), Field.id("alg", "-")))
        var n = 0
        for (alias in PlaygroundKeys.aliases()) {
            val t0 = now()
            try {
                deleteKeystoreKey(alias)
                tap.keyDelete(alias, now() - t0)
                n++
            } catch (t: Throwable) {
                tap.error(ErrorCode.of(t), now() - t0)
            }
        }
        synchronized(this) {
            if (lastSign?.key is KeyHandle.Platform) lastSign = null
            if (lastEncrypt?.key is KeyHandle.Platform) lastEncrypt = null
        }
        return n
    }
}
