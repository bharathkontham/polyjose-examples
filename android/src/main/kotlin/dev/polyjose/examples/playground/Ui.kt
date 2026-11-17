// Small framework-View helpers for the playground tabs (no AndroidX): text, buttons, info
// buttons that open the explanation of an id, pickers whose disabled rows show their reason and a
// Run anyway button, and the result card.
package dev.polyjose.examples.playground

import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Typeface
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.TextView

class Ui(val context: Context) {
    private val density = context.resources.displayMetrics.density
    fun dp(n: Int): Int = (n * density).toInt()

    fun text(s: CharSequence, size: Float = 14f, mono: Boolean = false, bold: Boolean = false): TextView = TextView(context).apply {
        text = s
        textSize = size
        if (mono) typeface = Typeface.MONOSPACE
        if (bold) setTypeface(typeface, Typeface.BOLD)
        setTextIsSelectable(mono)
    }

    fun small(s: CharSequence): TextView = text(s, 12f).apply { alpha = 0.75f }

    fun button(label: String, onClick: () -> Unit): Button = Button(context).apply {
        text = label
        isAllCaps = false
        setOnClickListener { onClick() }
    }

    fun smallButton(label: String, onClick: () -> Unit): Button = button(label, onClick).apply {
        textSize = 12f
        minHeight = 0
        minimumHeight = 0
        minWidth = 0
        minimumWidth = 0
        setPadding(dp(8), dp(2), dp(8), dp(2))
    }

    fun column(): LinearLayout = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }

    fun row(vararg views: View, weightFirst: Boolean = true): LinearLayout = LinearLayout(context).apply {
        orientation = LinearLayout.HORIZONTAL
        views.forEachIndexed { i, v ->
            val lp = if (i == 0 && weightFirst) LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            else LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT)
            addView(v, lp)
        }
    }

    /** An "i" button that shows the explanation of [id]. */
    fun info(id: String, device: DeviceInfo, level: Int? = null): Button = smallButton("i") { showInfo(id, device, level) }

    fun showInfo(id: String, device: DeviceInfo, level: Int? = null) {
        val message = if (id == "reason.api-level" && level != null) Explanations.apiLevel(level, device) else Explanations.text(id, device)
        AlertDialog.Builder(context).setTitle(id).setMessage(message).setPositiveButton("OK", null).show()
    }

    /** A section title with its info button. */
    fun section(title: String, infoId: String?, device: DeviceInfo): View {
        val t = text(title, 15f, bold = true).apply { setPadding(0, dp(12), 0, dp(2)) }
        return if (infoId == null) t else row(t, info(infoId, device))
    }

    fun copy(label: String, value: String) {
        context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(ClipData.newPlainText(label, value))
    }

    /** One row of a picker. A disabled row shows [reason] and, when given, a Run anyway button. */
    class Row<T>(
        val value: T,
        val label: String,
        val infoId: String? = null,
        val enabled: Boolean = true,
        val reason: Reason? = null,
        val note: String? = null,
        val runAnyway: (() -> Unit)? = null,
    )

    /** A list of radio rows; [onSelect] gets the tapped enabled row's value. */
    fun <T> picker(title: String, infoId: String?, rows: List<Row<T>>, selected: T, device: DeviceInfo, onSelect: (T) -> Unit): View {
        val box = column()
        box.addView(section(title, infoId, device))
        for (r in rows) {
            val radio = RadioButton(context).apply {
                text = r.label
                isChecked = r.value == selected
                isEnabled = r.enabled
                setOnClickListener { if (r.enabled) onSelect(r.value) }
            }
            box.addView(if (r.infoId != null) row(radio, info(r.infoId, device)) else radio)
            if (r.note != null) box.addView(small(r.note).apply { setPadding(dp(32), 0, 0, dp(2)) })
            val reason = r.reason
            if (!r.enabled && reason != null) {
                val line = small("Disabled: ${reason.line}").apply { setPadding(dp(32), 0, dp(4), 0) }
                val views = mutableListOf<View>(line, info(reason.id, device, reason.level))
                r.runAnyway?.let { run -> views += smallButton("Run anyway") { run() } }
                box.addView(row(*views.toTypedArray()))
            }
        }
        return box
    }
}

/** The result card of the Sign and Encrypt tabs (PLAYGROUND.md "The result card"). */
class ResultCard(private val ui: Ui, private val device: () -> DeviceInfo) {
    val view: LinearLayout = ui.column().apply { setPadding(0, ui.dp(12), 0, ui.dp(24)) }

    fun running(title: String) {
        view.removeAllViews()
        view.addView(ui.text(title, 15f, bold = true))
        view.addView(ui.small("Running… (a key with user authentication shows its prompt now)"))
    }

    fun show(r: Result) {
        view.removeAllViews()
        val d = device()
        view.addView(ui.text(r.title, 15f, bold = true))
        r.token?.let { token ->
            view.addView(ui.row(ui.text("Token", bold = true), ui.smallButton("Copy") { ui.copy("token", token.text) }))
            view.addView(ui.text(token.text, 12f, mono = true))
        }
        r.header?.let {
            view.addView(ui.text("Protected header", bold = true))
            view.addView(ui.text(it.text, 12f, mono = true))
        }
        r.outcome.forEach { view.addView(ui.text(it)) }
        r.claims?.let {
            view.addView(ui.text("Claims", bold = true))
            view.addView(ui.text(it.text, 12f, mono = true))
        }
        r.code?.let { code ->
            view.addView(ui.row(ui.text("Error code: ${code.name}", bold = true), ui.info("error.${code.name}", d)))
            view.addView(ui.small(Explanations.text("error.${code.name}", d)))
        }
        r.keyLives?.let { view.addView(ui.text("Key lives in: $it")) }
        r.alias?.let { view.addView(ui.small("Alias: $it" + if (r.aliasLeft == false) " (no key left under it)" else "")) }
        if (r.steps.isNotEmpty()) view.addView(ui.small("Times: " + r.steps.joinToString(" · ") { "${it.first} ${it.second} ms" }))
        r.notes.forEach { id -> view.addView(ui.row(ui.small(Explanations.text(id, d)), ui.info(id, d))) }
    }
}
