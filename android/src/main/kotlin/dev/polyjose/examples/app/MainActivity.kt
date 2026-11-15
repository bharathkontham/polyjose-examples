// The app's one screen: a button that runs every check of the catalog (Catalog.kt) and the
// result lines. Each line also goes to logcat under the tag POLYJOSE, which run.sh reads.
//
//   adb shell am start -n dev.polyjose.examples/.app.MainActivity --ez autorun true
//
// starts the run without a tap.
package dev.polyjose.examples.app

import android.app.Activity
import android.content.Intent
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import dev.polyjose.examples.BuildConfig
import dev.polyjose.version

class MainActivity : Activity() {
    private lateinit var button: Button
    private lateinit var output: TextView
    private var running = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()
        button = Button(this).apply {
            text = "Run the checks"
            setOnClickListener { runChecks() }
        }
        output = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 12f
            setTextIsSelectable(true)
        }
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
            addView(button)
            addView(output)
        }
        setContentView(ScrollView(this).apply {
            fitsSystemWindows = true
            addView(column)
        })
        if (savedInstanceState == null) autorun(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        autorun(intent)
    }

    private fun autorun(intent: Intent?) {
        if (intent?.getBooleanExtra(EXTRA_AUTORUN, false) == true) runChecks()
    }

    /** Runs the catalog off the main thread: polyjose calls are synchronous and do real work. */
    private fun runChecks() {
        if (running) return
        running = true
        button.isEnabled = false
        output.text = ""
        Thread {
            val polyjose = runCatching { version() }.getOrElse { "unavailable (${it.javaClass.simpleName})" }
            val info = listOf(
                "polyjose $polyjose through dev.polyjose:polyjose (${BuildConfig.POLYJOSE_SOURCE}), " +
                    "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) on ${Build.MODEL}",
            )
            runCatalog(info) { line ->
                Log.i(TAG, line)
                runOnUiThread { output.append(line + "\n") }
            }
            runOnUiThread {
                running = false
                button.isEnabled = true
            }
        }.start()
    }

    companion object {
        /** The logcat tag of every result line. */
        const val TAG = "POLYJOSE"

        /** A boolean extra: true starts the run as soon as the activity opens. */
        const val EXTRA_AUTORUN = "autorun"
    }
}
