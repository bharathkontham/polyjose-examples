// The demo walk (PLAYGROUND.md "Demo walk"): `run.sh --playground` starts the activity with
// `--ez playgroundDemo true`, and the walk runs, through the engine the buttons call:
// - every enabled cell of the support matrix that needs no prompt, which must succeed;
// - Run anyway on every disabled cell, which must give the code of its row (and leave no key);
// - every failure action, which must give its code (a disabled one must show its reason);
// - the Keys tab's actions.
// Enabled cells with user authentication are skipped: no one is there to authenticate. Each step
// prints `PLAYGROUND OK <name>` or `PLAYGROUND FAIL <name>: <what>` (codes only), and the walk ends
// with `POLYJOSE-PLAYGROUND: N/M OK` after deleting its keys.
package dev.polyjose.examples.playground

import dev.polyjose.AndroidKeystoreKey

class DemoWalk(private val p: Playground, private val emit: (String) -> Unit) {
    private class Step(val name: String, val check: () -> String?)

    private val steps = ArrayList<Step>()
    private var skipped = 0

    fun start() {
        val device = p.device()
        Session.executor.execute {
            emit("# playground demo walk: Android ${device.release} (API ${device.api}) on ${device.model}, StrongBox ${device.hasStrongBox}, lock screen ${device.lockScreen}")
            build(device)
            var ok = 0
            for (s in steps) {
                val problem = try {
                    s.check()
                } catch (t: Throwable) {
                    "unexpected ${ErrorCode.of(t).name}"
                }
                if (problem == null) {
                    ok++
                    emit("PLAYGROUND OK ${s.name}")
                } else {
                    emit("PLAYGROUND FAIL ${s.name}: $problem")
                }
            }
            val cleanup = Session.engine.deleteAll()
            val left = PlaygroundKeys.aliases().size
            if (left == 0) ok++ else emit("PLAYGROUND FAIL keys/cleanup: $left playground keys left")
            if (left == 0) emit("PLAYGROUND OK keys/cleanup ($cleanup deleted)")
            emit("# $skipped enabled cells with user authentication skipped (they prompt)")
            emit("# LOG lines mirrored: ${Session.log.mirrored}")
            emit("POLYJOSE-PLAYGROUND: $ok/${steps.size + 1} OK")
            p.activity.runOnUiThread { p.refreshAll() }
        }
    }

    private fun step(name: String, check: () -> String?) {
        steps += Step(name, check)
    }

    private fun name(sel: Selection, what: String): String = buildString {
        append(if (sel.kind == Kind.Sign) "sign/" else "encrypt/")
        append(what).append('/')
        append(sel.store.id)
        if (sel.store == Store.StrongBox) append('-').append(sel.mode.id)
        append('/').append(sel.alg)
        if (sel.kind == Kind.Encrypt) {
            if (Matrix.isEcdh(sel.alg)) append('/').append(sel.crv)
            append('/').append(sel.enc)
        }
        if ((Matrix.isRsaSign(sel.alg) || sel.alg == "RSA-OAEP-256") && sel.store != Store.Software) append('/').append(sel.rsaSize)
        when (val a = sel.auth) {
            is Auth.TimeBound -> append("/time-bound-${a.seconds}s").append(if (a.deviceCredential) "-credential" else "")
            is Auth.PerUse -> append("/per-use").append(if (a.deviceCredential) "-credential" else "")
            Auth.None -> Unit
        }
    }

    /** The outcome of [r] against [expected] (null: success), in codes only. */
    private fun judge(r: Result, expected: String?, device: DeviceInfo, sel: Selection): String? {
        val got = r.code?.name
        if (got != expected) return "expected ${expected ?: "success"}, got ${got ?: "success"}"
        if (expected == null) {
            if (sel.kind == Kind.Sign && !r.verified) return "did not verify"
            if (sel.kind == Kind.Encrypt && r.decryptedEqual != true) return "plaintext differs"
            // Preferred without StrongBox: anywhere but StrongBox, and the key works (it just did).
            if (sel.store == Store.StrongBox && sel.mode == StrongBoxMode.Preferred && !device.hasStrongBox &&
                r.level == AndroidKeystoreKey.SecurityLevel.StrongBox
            ) return "Preferred reports StrongBox without StrongBox"
            // Required: StrongBox (below API 31 the platform can't name it, so it isn't checked there).
            if (sel.store == Store.StrongBox && sel.mode == StrongBoxMode.Required && device.api >= Matrix.NAMED_LEVEL_API &&
                r.level != AndroidKeystoreKey.SecurityLevel.StrongBox
            ) return "Required reports ${r.level}"
        } else if (r.alias != null && r.aliasLeft != false) {
            return "a key was left under the alias"
        }
        return null
    }

    private val platformStores = listOf(
        Store.Keystore to StrongBoxMode.Preferred,
        Store.StrongBox to StrongBoxMode.Preferred,
        Store.StrongBox to StrongBoxMode.Required,
    )
    private val allStores = listOf(Store.Software to StrongBoxMode.Preferred) + platformStores

    /** A cell: an enabled one succeeds (then a JWT with the same key, for signing), a disabled one runs anyway. */
    private fun cell(sel: Selection, device: DeviceInfo, jwtToo: Boolean = false) {
        val c = sel.cell(device)
        if (c.enabled && c.prompted) {
            skipped++
            return
        }
        if (c.enabled) {
            var alias: String? = null
            step(name(sel, if (sel.kind == Kind.Sign) "jws-sign-verify" else "jwe-round-trip")) {
                val r = Session.engine.perform(Request(sel), device)
                alias = r.alias
                judge(r, null, device, sel)
            }
            if (jwtToo) {
                step(name(sel, "jwt-sign-verify")) {
                    // The key the step above created, chosen as on the Key picker (Open again for a platform key).
                    val key = alias?.let { KeyChoice.Platform(it) } ?: KeyChoice.New
                    val r = Session.engine.perform(Request(sel.copy(jwt = true, key = key)), device)
                    judge(r, null, device, sel)
                }
            }
        } else {
            step(name(sel, "anyway")) {
                val r = Session.engine.perform(Request(sel, anyway = true), device)
                judge(r, c.expected, device, sel)
            }
        }
    }

    private fun build(d: DeviceInfo) {
        // 1. Signing: every algorithm in every store (RSA at 2048 bits), JWS and JWT.
        for ((store, mode) in allStores) for (alg in Matrix.SIGN_ALGS) {
            cell(Selection(Kind.Sign, store = store, mode = mode, alg = alg), d, jwtToo = true)
        }
        // 2. The RSA sizes.
        for ((store, mode) in platformStores) for ((alg, size) in listOf("PS256" to 3072, "RS256" to 4096)) {
            cell(Selection(Kind.Sign, store = store, mode = mode, alg = alg, rsaSize = size), d)
        }
        // 3. Decryption: every alg (every curve for ECDH-ES) in every store, with A256GCM.
        for ((store, mode) in allStores) for (alg in Matrix.JWE_ALGS) {
            val curves = if (Matrix.isEcdh(alg)) Matrix.CURVES else listOf("P-256")
            for (crv in curves) cell(Selection(Kind.Encrypt, store = store, mode = mode, alg = alg, crv = crv), d)
        }
        for ((store, mode) in platformStores) cell(Selection(Kind.Encrypt, store = store, mode = mode, alg = "RSA-OAEP-256", rsaSize = 3072), d)
        // 4. Every enc, in software and in the Keystore, and with `dir` (its key sized by enc).
        for (enc in Matrix.ENCS.filter { it != "A256GCM" }) { // A256GCM: section 3
            cell(Selection(Kind.Encrypt, store = Store.Software, alg = "ECDH-ES", enc = enc), d)
            cell(Selection(Kind.Encrypt, store = Store.Keystore, alg = "ECDH-ES+A128KW", enc = enc), d)
            cell(Selection(Kind.Encrypt, store = Store.Software, alg = "dir", enc = enc), d)
        }
        // 5. User authentication: enabled cells prompt and are skipped; disabled ones run anyway.
        val auths = listOf(Auth.TimeBound(30, true), Auth.TimeBound(30, false), Auth.PerUse(false), Auth.PerUse(true))
        for ((store, mode) in platformStores) for (auth in auths) {
            cell(Selection(Kind.Sign, store = store, mode = mode, alg = "ES256", auth = auth), d)
            cell(Selection(Kind.Encrypt, store = store, mode = mode, alg = "ECDH-ES+A256KW", auth = auth), d)
            cell(Selection(Kind.Encrypt, store = store, mode = mode, alg = "RSA-OAEP-256", auth = auth), d)
        }
        // 6. The failure actions.
        val signKeys = listOf(
            Store.Software to "ES256", Store.Software to "HS256", Store.Software to "EdDSA", Store.Software to "RS256",
            Store.Keystore to "ES256", Store.Keystore to "PS256", Store.StrongBox to "ES256",
        )
        for ((store, alg) in signKeys) {
            val sel = Selection(Kind.Sign, jwt = true, store = store, alg = alg)
            if (!sel.cell(d).enabled) continue
            for (f in Failure.values().filter { it.kind == Kind.Sign }) failureStep(sel, f, d)
        }
        val encryptKeys = listOf(
            Triple(Store.Software, "ECDH-ES+A256KW", "P-256"), Triple(Store.Software, "ECDH-ES", "X25519"), Triple(Store.Software, "A256KW", "P-256"),
            Triple(Store.Software, "A128GCMKW", "P-256"), Triple(Store.Software, "dir", "P-256"), Triple(Store.Software, "RSA-OAEP-256", "P-256"),
            Triple(Store.Keystore, "ECDH-ES+A256KW", "P-256"), Triple(Store.Keystore, "ECDH-ES", "P-384"), Triple(Store.Keystore, "RSA-OAEP-256", "P-256"),
        )
        for ((store, alg, crv) in encryptKeys) {
            val sel = Selection(Kind.Encrypt, store = store, alg = alg, crv = crv)
            if (!sel.cell(d).enabled) continue
            for (f in Failure.values().filter { it.kind == Kind.Encrypt }) failureStep(sel, f, d)
        }
        // 7. The buttons on their own: Sign, then Verify; Encrypt, then Decrypt.
        buttonPair(Selection(Kind.Sign, store = Store.Keystore, alg = "ES256"), Action.JwsSign, Action.JwsVerify, d)
        buttonPair(Selection(Kind.Sign, jwt = true, store = Store.Software, alg = "ES384"), Action.JwtSign, Action.JwtVerify, d)
        buttonPair(Selection(Kind.Encrypt, store = Store.Software, alg = "ECDH-ES+A256KW"), Action.JweEncrypt, Action.JweDecrypt, d)
        if (Selection(Kind.Encrypt, store = Store.Keystore, alg = "ECDH-ES").cell(d).enabled) {
            buttonPair(Selection(Kind.Encrypt, store = Store.Keystore, alg = "ECDH-ES"), Action.JweEncrypt, Action.JweDecrypt, d)
        }
        // 8. The Keys tab.
        keysTab(d)
    }

    private fun failureStep(sel: Selection, f: Failure, d: DeviceInfo) {
        val reason = f.reason(sel)
        val s = if (f == Failure.SignExpired) sel.copy(jwt = true) else sel
        step(name(s, "failure-${f.id}")) {
            val r = Session.engine.perform(Request(s, failure = f), d)
            when {
                reason != null -> if (r.code == null && reason.id in r.notes) null else "expected disabled (${reason.id}), got ${r.code?.name ?: "no reason"}"
                r.code?.name != f.expected -> "expected ${f.expected}, got ${r.code?.name ?: "success"}"
                else -> null
            }
        }
    }

    private fun buttonPair(sel: Selection, first: Action, second: Action, d: DeviceInfo) {
        step(name(sel, first.id)) {
            val r = Session.engine.perform(Request(sel, action = first), d)
            if (r.code != null) "expected success, got ${r.code?.name}" else if (r.token == null) "no token" else null
        }
        step(name(sel, second.id)) {
            val r = Session.engine.perform(Request(sel, action = second), d)
            if (r.code != null) "expected success, got ${r.code?.name}" else judge(r, null, d, sel)
        }
    }

    private fun keysTab(d: DeviceInfo) {
        var alias: String? = null
        step("keys/create/keystore/ES256") {
            val r = Session.engine.createKey(Selection(Kind.Sign, store = Store.Keystore, alg = "ES256"), d)
            alias = r.alias
            if (r.code != null) "expected success, got ${r.code?.name}" else if (alias?.startsWith(PlaygroundKeys.PREFIX) != true) "no alias" else null
        }
        step("keys/list") {
            if (alias != null && alias in PlaygroundKeys.aliases()) null else "the new key is not listed"
        }
        step("keys/open-again") {
            val o = Session.engine.openAgain(alias ?: return@step "no alias", d)
            when {
                o.code != null -> "expected success, got ${o.code.name}"
                o.thumbprint.isNullOrEmpty() || o.jwk == null -> "no public JWK or thumbprint"
                o.jwk.text.contains("[withheld]") -> "the public JWK was withheld"
                else -> null
            }
        }
        step("keys/delete") {
            val a = alias ?: return@step "no alias"
            val code = Session.engine.delete(a)
            if (code != null) "expected success, got ${code.name}" else if (PlaygroundKeys.exists(a)) "the key is still there" else null
        }
        step("keys/open-deleted") {
            val o = Session.engine.openAgain(alias ?: return@step "no alias", d)
            if (o.code?.name == "KeyNotFound") null else "expected KeyNotFound, got ${o.code?.name ?: "success"}"
        }
        step("keys/software-public-jwk") {
            val k = Session.engine.softwareKeys().lastOrNull { !it.isOct } ?: return@step "no software key"
            val o = Session.engine.showSoftware(k.id) ?: return@step "not found"
            if (o.jwk == null || o.jwk.text.contains("[withheld]") || o.thumbprint.isNullOrEmpty()) "no public JWK" else null
        }
    }
}
