// The Sign and Encrypt tabs (PLAYGROUND.md "Tabs"): pickers built from the support matrix
// (Matrix.kt), the action buttons, the Try a failure menu and the result card. Every row has an
// info button; a disabled row shows its reason and Run anyway, which makes the call and shows the
// library's code. Changing a picker rebuilds the form.
package dev.polyjose.examples.playground

import android.app.AlertDialog
import android.widget.CheckBox
import android.widget.ScrollView

class OperationTab(private val p: Playground, val kind: Kind) {
    private val ui = p.ui
    var sel = Selection(kind)
        private set
    private val form = ui.column()
    private val card = ResultCard(ui) { p.device() }
    val view = ScrollView(p.activity).apply {
        addView(ui.column().apply {
            setPadding(ui.dp(16), ui.dp(8), ui.dp(16), ui.dp(16))
            addView(form)
            addView(card.view)
        })
    }

    init {
        rebuild()
    }

    fun refresh() = rebuild()

    private fun set(s: Selection) {
        sel = s
        rebuild()
    }

    private fun run(req: Request) = p.submit(req, card) { r ->
        // A new time-bound key is chosen for the next tap, so Authenticate now, then Sign, uses it.
        if (req.sel.auth is Auth.TimeBound && req.sel.key == KeyChoice.New && r.aliasLeft == true && r.alias != null) {
            set(sel.copy(key = KeyChoice.Platform(r.alias!!)))
        } else {
            rebuild()
        }
    }

    private fun rebuild() {
        val d = p.device()
        val s = sel
        form.removeAllViews()
        form.addView(ui.section(if (kind == Kind.Sign) "Sign" else "Encrypt", if (kind == Kind.Sign) "tab.sign" else "tab.encrypt", d))

        if (kind == Kind.Sign) {
            form.addView(
                ui.picker("Operation", "option.payload", listOf(Ui.Row(false, "JWS compact"), Ui.Row(true, "JWT")), s.jwt, d) {
                    set(s.copy(jwt = it))
                },
            )
        }

        val stores = Store.values().map { st ->
            Ui.Row(st, st.label, st.explanation, note = if (st == Store.StrongBox && !d.hasStrongBox) "No StrongBox on this device: Preferred falls back to the TEE, Required fails." else null)
        }
        form.addView(ui.picker(if (kind == Kind.Sign) "Key store" else "Key store that decrypts", null, stores, s.store, d) { set(s.copy(store = it, key = KeyChoice.New)) })

        if (s.store == Store.StrongBox) {
            val modes = StrongBoxMode.values().map { m ->
                Ui.Row(m, m.label, m.explanation, note = if (m == StrongBoxMode.Required && !d.hasStrongBox) "${Matrix.NO_STRONGBOX.line}: creating a key fails" else null)
            }
            form.addView(ui.picker("StrongBox mode", null, modes, s.mode, d) { set(s.copy(mode = it, key = KeyChoice.New)) })
        }

        val algs = if (kind == Kind.Sign) Matrix.SIGN_ALGS else Matrix.JWE_ALGS
        val algRows = algs.map { a ->
            val c = s.copy(alg = a).cell(d)
            Ui.Row(a, a, "alg.$a", c.enabled, c.reason, runAnyway = { run(Request(s.copy(alg = a, key = KeyChoice.New), anyway = true)) })
        }
        form.addView(ui.picker(if (kind == Kind.Sign) "Algorithm" else "Key management (alg)", null, algRows, s.alg, d) { set(s.copy(alg = it, key = KeyChoice.New)) })

        if (kind == Kind.Encrypt) {
            form.addView(ui.picker("Content encryption (enc)", null, Matrix.ENCS.map { Ui.Row(it, it, "enc.$it") }, s.enc, d) { set(s.copy(enc = it)) })
            if (Matrix.isEcdh(s.alg)) {
                val curves = Matrix.CURVES.map { c ->
                    val cell = s.copy(crv = c).cell(d)
                    Ui.Row(c, c, "crv.$c", cell.enabled, cell.reason, runAnyway = { run(Request(s.copy(crv = c, key = KeyChoice.New), anyway = true)) })
                }
                form.addView(ui.picker("Curve", "option.curve", curves, s.crv, d) { set(s.copy(crv = it, key = KeyChoice.New)) })
            }
        }

        val rsa = Matrix.isRsaSign(s.alg) || s.alg == "RSA-OAEP-256"
        if (rsa && s.store == Store.Software) {
            form.addView(ui.row(ui.small("Software RSA uses the RFC 7515 A.2 test key (2048 bits)."), ui.info("key.test-rsa", d)))
        } else if (rsa) {
            val sizes = Matrix.RSA_SIZES.map { n ->
                val cell = s.copy(rsaSize = n).cell(d)
                Ui.Row(n, "$n bits", null, cell.enabled, cell.reason, runAnyway = { run(Request(s.copy(rsaSize = n, key = KeyChoice.New), anyway = true)) })
            }
            form.addView(ui.picker("RSA size", "option.rsa-size", sizes, s.rsaSize, d) { set(s.copy(rsaSize = it, key = KeyChoice.New)) })
        }

        if (s.store != Store.Software) addAuth(s, d)
        addKeyChoice(s, d)

        // Buttons
        val cell = s.cell(d)
        val actions = when {
            kind == Kind.Encrypt -> listOf(Action.JweEncrypt, Action.JweDecrypt, Action.JweRoundTrip)
            s.jwt -> listOf(Action.JwtSign, Action.JwtVerify, Action.JwtSignVerify)
            else -> listOf(Action.JwsSign, Action.JwsVerify, Action.JwsSignVerify)
        }
        val usable = cell.enabled || s.key != KeyChoice.New
        val buttons = actions.map { a ->
            ui.button(a.label) { run(Request(s, action = a)) }.apply { isEnabled = usable || !a.signs }
        }
        form.addView(ui.row(*buttons.toTypedArray(), weightFirst = false).apply { setPadding(0, ui.dp(12), 0, 0) })
        if (!usable) form.addView(ui.small("This combination is disabled (${cell.reason?.line}): use Run anyway on its row."))
        form.addView(ui.button("Try a failure…") { failureMenu(s, usable) }.apply { isEnabled = usable })
    }

    private fun addAuth(s: Selection, d: DeviceInfo) {
        val current = s.auth
        val seconds = (current as? Auth.TimeBound)?.seconds ?: 30
        val dc = when (current) {
            is Auth.TimeBound -> current.deviceCredential
            is Auth.PerUse -> current.deviceCredential
            Auth.None -> true
        }
        val options = listOf<Auth>(Auth.None, Auth.TimeBound(seconds, dc), Auth.PerUse(dc))
        val labels = mapOf("none" to "None", "time-bound" to "Time-bound: authenticate, then a window", "per-use" to "Per use: a prompt for each operation")
        val rows = options.map { a ->
            val reason = Matrix.authReason(s.store, s.alg, a, d)
            Ui.Row(a.id, labels.getValue(a.id), "option.auth.${a.id}", reason == null, reason, runAnyway = { run(Request(s.copy(auth = a, key = KeyChoice.New), anyway = true)) })
        }
        form.addView(ui.picker("User authentication", null, rows, current.id, d) { id -> set(s.copy(auth = options.first { it.id == id }, key = KeyChoice.New)) })
        if (current is Auth.TimeBound) {
            form.addView(
                ui.picker("Window", null, Matrix.AUTH_SECONDS.map { Ui.Row(it, "$it seconds") }, current.seconds, d) {
                    set(s.copy(auth = current.copy(seconds = it), key = KeyChoice.New))
                },
            )
        }
        if (current.prompted) {
            val free = d.api >= Matrix.DEVICE_CREDENTIAL_API
            val box = CheckBox(p.activity).apply {
                text = "Allow the device credential (PIN, pattern, password)"
                isChecked = Matrix.deviceCredential(current, d)
                isEnabled = free
                setOnClickListener {
                    val v = isChecked
                    set(s.copy(auth = if (current is Auth.TimeBound) current.copy(deviceCredential = v) else Auth.PerUse(v), key = KeyChoice.New))
                }
            }
            form.addView(ui.row(box, ui.info("option.auth.device-credential", d)))
            if (!free) form.addView(ui.small("Below API 30 the platform decides."))
        }
        if (current is Auth.TimeBound) {
            form.addView(ui.button("Authenticate now") { p.authenticateNow(s) }.apply { isEnabled = d.api >= Matrix.PROMPT_API })
        }
    }

    private fun addKeyChoice(s: Selection, d: DeviceInfo) {
        val rows = mutableListOf<Ui.Row<KeyChoice>>(Ui.Row(KeyChoice.New, "New key"))
        if (s.store == Store.Software) {
            Session.engine.softwareKeys().filter { it.alg == s.alg && (it.crv == null || it.crv == s.crv) }.forEach {
                rows += Ui.Row(KeyChoice.Software(it.id), "Software key ${it.id} (${it.kty}${if (it.testKey) ", test key" else ""})")
            }
        } else {
            val algorithm = Matrix.keySpec(s.alg, s.crv, s.rsaSize)?.algorithm
            if (algorithm != null) {
                runCatching { PlaygroundKeys.aliases() }.getOrDefault(emptyList())
                    .filter { PlaygroundKeys.algorithmOf(it) == algorithm }
                    .forEach { rows += Ui.Row(KeyChoice.Platform(it), it.removePrefix(PlaygroundKeys.PREFIX)) }
            }
        }
        if (s.key != KeyChoice.New && rows.none { it.value == s.key }) {
            sel = s.copy(key = KeyChoice.New)
        }
        form.addView(ui.picker("Key", null, rows, sel.key, d) { set(sel.copy(key = it)) })
    }

    private fun failureMenu(s: Selection, usable: Boolean) {
        if (!usable) return
        val d = p.device()
        val failures = Failure.values().filter { it.kind == kind && (it != Failure.SignExpired || s.jwt) }
        val labels = failures.map { f -> f.reason(s)?.let { "${f.label} (disabled: ${it.line})" } ?: f.label }.toTypedArray()
        AlertDialog.Builder(p.activity)
            .setTitle("Try a failure")
            .setItems(labels) { _, i ->
                val f = failures[i]
                val reason = f.reason(s)
                if (reason != null) ui.showInfo(reason.id, d, reason.level) else run(Request(s, failure = f))
            }
            .setNegativeButton("Close", null)
            .show()
    }
}
