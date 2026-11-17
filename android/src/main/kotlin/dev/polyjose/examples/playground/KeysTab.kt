// The Keys tab (PLAYGROUND.md "Tabs", "Key names"): the "This device" card, the playground's
// Keystore keys (aliases with the playground prefix) with their algorithm, the level the platform
// reports and their authentication, and this session's software keys. Each key has Open again
// (public JWK and RFC 7638 thumbprint) and Delete; the tab has Create key and Delete all.
package dev.polyjose.examples.playground

import android.app.AlertDialog
import android.widget.LinearLayout
import android.widget.ScrollView
import dev.polyjose.examples.openKeystoreKey

class KeysTab(private val p: Playground) {
    private val ui = p.ui
    private val deviceCard = ui.column()
    private val list = ui.column()
    private val status = ui.small("")
    val view = ScrollView(p.activity).apply {
        addView(ui.column().apply {
            setPadding(ui.dp(16), ui.dp(8), ui.dp(16), ui.dp(16))
            addView(ui.section("Keys", "tab.keys", p.device()))
            addView(deviceCard)
            addView(ui.row(ui.button("Create key…") { createMenu() }, ui.button("Delete all playground keys") { deleteAll() }, weightFirst = false))
            addView(ui.button("Refresh") { refresh() })
            addView(status)
            addView(list)
        })
    }

    /** One playground key as listed: read from `KeyInfo` and `AndroidKeystoreKey.open`. */
    private class Listed(val alias: String, val algorithm: String, val info: PlaygroundKeys.Info?, val level: String)

    fun refresh() {
        showDevice(p.device())
        p.background({
            runCatching {
                PlaygroundKeys.aliases().map { alias ->
                    val algorithm = PlaygroundKeys.algorithmOf(alias)
                    val info = runCatching { PlaygroundKeys.info(alias) }.getOrNull()
                    val level = try { openKeystoreKey(alias, algorithm).securityLevel.name } catch (t: Throwable) { "not usable: ${ErrorCode.of(t).name}" }
                    Listed(alias, algorithm, info, level)
                }
            }.getOrDefault(emptyList())
        }) { render(it) }
    }

    private fun showDevice(d: DeviceInfo) {
        deviceCard.removeAllViews()
        deviceCard.addView(ui.text("This device", 15f, bold = true))
        fun yes(b: Boolean) = if (b) "yes" else "no"
        deviceCard.addView(
            ui.text(
                "Model: ${d.model}\nAndroid ${d.release}, API ${d.api}\nEmulator: ${yes(d.emulator)}" +
                    (if (d.emulator) " (its keys are software, whatever it reports)" else "") +
                    "\nStrongBox (FEATURE_STRONGBOX_KEYSTORE): ${yes(d.hasStrongBox)}\nSecure lock screen (isDeviceSecure): ${yes(d.lockScreen)}",
                13f,
            ),
        )
    }

    private fun render(keys: List<Listed>) {
        val d = p.device()
        list.removeAllViews()
        list.addView(ui.text("Android Keystore (${keys.size})", 15f, bold = true).apply { setPadding(0, ui.dp(12), 0, 0) })
        if (keys.isEmpty()) list.addView(ui.small("No playground keys. Sign or encrypt with a platform store, or tap Create key."))
        for (k in keys) {
            val box = ui.column().apply { setPadding(0, ui.dp(8), 0, ui.dp(8)) }
            val detail = ui.column()
            box.addView(ui.text(k.alias, 12f, mono = true))
            val size = k.info?.keySize?.let { if (k.algorithm.startsWith("ES") || k.algorithm == "ECDH-ES") "P-$it" else "$it bits" } ?: "?"
            box.addView(ui.small("${k.algorithm} · $size · lives in: ${k.level} · authentication: ${k.info?.auth ?: "?"}"))
            box.addView(
                ui.row(
                    ui.smallButton("Open again") { openAgain(k.alias, detail) },
                    ui.smallButton("Delete") { delete(k.alias) },
                    ui.info("store.keystore", d),
                    weightFirst = false,
                ),
            )
            box.addView(detail)
            list.addView(box)
        }
        val soft = Session.engine.softwareKeys()
        list.addView(ui.row(ui.text("Software, in app memory (${soft.size})", 15f, bold = true), ui.info("store.software", d)).apply { setPadding(0, ui.dp(12), 0, 0) })
        for (k in soft.asReversed()) {
            val detail = ui.column()
            val box = ui.column().apply { setPadding(0, ui.dp(6), 0, ui.dp(6)) }
            val summary = buildString {
                append("Software key ${k.id} · ${k.alg} · kty ${k.kty}")
                k.kid?.let { append(" · kid $it") }
                k.bits?.let { append(" · $it bits") }
                if (k.testKey) append(" · test key")
            }
            box.addView(ui.small(summary))
            if (!k.isOct) box.addView(ui.smallButton("Public JWK and thumbprint") { showSoftware(k.id, detail) })
            box.addView(detail)
            list.addView(box)
        }
    }

    private fun showOpened(o: Engine.Opened, detail: LinearLayout) {
        detail.removeAllViews()
        val d = p.device()
        o.code?.let {
            detail.addView(ui.row(ui.text("Error code: ${it.name}", bold = true), ui.info("error.${it.name}", d)))
            return
        }
        o.level?.let { detail.addView(ui.text("Key lives in: $it", 13f)) }
        o.jwk?.let { jwk ->
            detail.addView(ui.row(ui.text("Public JWK", 13f, bold = true), ui.smallButton("Copy") { ui.copy("public JWK", jwk.text) }))
            detail.addView(ui.text(jwk.text, 11f, mono = true))
        }
        o.thumbprint?.let { detail.addView(ui.text("RFC 7638 thumbprint: $it", 12f, mono = true)) }
    }

    private fun openAgain(alias: String, detail: LinearLayout) {
        val d = p.device()
        p.background({ Session.engine.openAgain(alias, d) }) { showOpened(it, detail) }
    }

    private fun showSoftware(id: Int, detail: LinearLayout) {
        p.background({ Session.engine.showSoftware(id) }) { o -> if (o != null) showOpened(o, detail) }
    }

    private fun delete(alias: String) {
        p.background({ Session.engine.delete(alias) }) { code ->
            status.text = code?.let { "Delete: $it" } ?: "Deleted ${alias.removePrefix(PlaygroundKeys.PREFIX)}."
            p.refreshAll()
        }
    }

    private fun deleteAll() {
        p.background({ Session.engine.deleteAll() }) { n ->
            status.text = "Deleted ${n.platform} Keystore keys and ${n.software} software keys."
            p.refreshAll()
        }
    }

    /** Create key: the enabled cells without user authentication, one per line. */
    private fun createMenu() {
        val d = p.device()
        val choices = mutableListOf<Selection>()
        val specs = listOf(
            Selection(Kind.Sign, alg = "ES256"), Selection(Kind.Sign, alg = "ES384"), Selection(Kind.Sign, alg = "ES512"),
            Selection(Kind.Sign, alg = "RS256"), Selection(Kind.Sign, alg = "PS256"), Selection(Kind.Sign, alg = "RS384"),
            Selection(Kind.Sign, alg = "RS512"), Selection(Kind.Sign, alg = "PS384"), Selection(Kind.Sign, alg = "PS512"),
            Selection(Kind.Encrypt, alg = "ECDH-ES", crv = "P-256"), Selection(Kind.Encrypt, alg = "ECDH-ES", crv = "P-384"),
            Selection(Kind.Encrypt, alg = "ECDH-ES", crv = "P-521"), Selection(Kind.Encrypt, alg = "RSA-OAEP-256"),
        )
        for (s in specs) {
            for ((store, mode) in listOf(Store.Keystore to StrongBoxMode.Preferred, Store.StrongBox to StrongBoxMode.Preferred, Store.StrongBox to StrongBoxMode.Required)) {
                val c = s.copy(store = store, mode = mode)
                if (c.cell(d).enabled) choices += c
            }
        }
        val labels = choices.map { "${it.alg}${if (it.alg == "ECDH-ES") " ${it.crv}" else ""} · ${it.storeLabel}" }.toTypedArray()
        AlertDialog.Builder(p.activity)
            .setTitle("Create key (no user authentication)")
            .setItems(labels) { _, i ->
                val c = choices[i]
                p.background({ Session.engine.createKey(c, d) }) { r ->
                    status.text = r.code?.let { "Create key: $it" } ?: r.outcome.joinToString(" ")
                    p.refreshAll()
                }
            }
            .setNegativeButton("Close", null)
            .show()
    }
}
