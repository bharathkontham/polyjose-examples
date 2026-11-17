// The Log tab (PLAYGROUND.md "Log"): every tap, newest first, one line per step, with Copy all
// (ClipboardManager), Share (Intent.ACTION_SEND) and Clear. The log holds no secrets, so it can be
// copied and shared as it is.
package dev.polyjose.examples.playground

import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.widget.ScrollView

class LogTab(private val p: Playground) {
    private val ui = p.ui
    private val body = ui.text("", 11f, mono = true)
    private val main = Handler(Looper.getMainLooper())
    private var pending = false

    /** Whether the tab is on screen: the text is rebuilt only then. */
    var visible = false
        set(value) {
            field = value
            if (value) refresh()
        }

    val view = ScrollView(p.activity).apply {
        addView(ui.column().apply {
            setPadding(ui.dp(16), ui.dp(8), ui.dp(16), ui.dp(16))
            addView(ui.section("Log", "tab.log", p.device()))
            addView(
                ui.row(
                    ui.button("Copy all") { ui.copy("polyjose playground log", Session.log.text(SHARE_LIMIT)) },
                    ui.button("Share") { share() },
                    ui.button("Clear") { Session.log.clear() },
                    weightFirst = false,
                ),
            )
            addView(body)
        })
    }

    // Lines arrive on any thread; the text is rebuilt at most every 300 ms, on the main thread.
    private val listener: () -> Unit = {
        if (visible) main.post {
            if (!pending) {
                pending = true
                main.postDelayed({
                    pending = false
                    refresh()
                }, 300)
            }
        }
    }

    init {
        Session.log.onChange = listener
    }

    /** When the activity goes: stop listening, unless a newer activity's tab already does. */
    fun detach() {
        if (Session.log.onChange === listener) Session.log.onChange = null
    }

    fun refresh() {
        if (visible) body.text = Session.log.text(DISPLAY_LIMIT)
    }

    private fun share() {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "polyjose playground log")
            putExtra(Intent.EXTRA_TEXT, Session.log.text(SHARE_LIMIT))
        }
        p.activity.startActivity(Intent.createChooser(send, "Share the log"))
    }

    companion object {
        /** An intent or a clip of more than about 1 MB fails, so the oldest taps are left out beyond this. */
        const val SHARE_LIMIT = 400_000
        const val DISPLAY_LIMIT = 200_000
    }
}
