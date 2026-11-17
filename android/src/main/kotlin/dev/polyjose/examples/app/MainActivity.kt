// The app's one activity: five tabs, Checks, Sign, Encrypt, Keys and Log, in a bottom row. It opens
// on Checks: a button that runs every check of the catalog (Catalog.kt) and the result lines. Each
// line also goes to logcat under the tag POLYJOSE, which run.sh reads. The other four tabs are the
// playground (../playground/, PLAYGROUND.md at the repository root).
//
//   adb shell am start -n dev.polyjose.examples/.app.MainActivity --ez autorun true
//
// starts the checks without a tap, and `--ez playgroundDemo true` starts the playground's demo walk.
package dev.polyjose.examples.app

import android.app.Activity
import android.content.Intent
import android.graphics.Typeface
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import dev.polyjose.examples.BuildConfig
import dev.polyjose.examples.hasStrongBox
import dev.polyjose.examples.playground.DemoWalk
import dev.polyjose.examples.playground.Playground
import dev.polyjose.examples.playground.PromptHost
import dev.polyjose.examples.playground.Session
import dev.polyjose.version

class MainActivity : Activity(), PromptHost {
    private lateinit var button: Button
    private lateinit var output: TextView
    private lateinit var playground: Playground
    private lateinit var tabs: List<Pair<Button, View>>
    private var running = false
    private var walking = false

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
        val checks = ScrollView(this).apply { addView(column) }

        playground = Playground(this, this)
        val content = FrameLayout(this)
        val views = listOf<View>(checks, playground.sign.view, playground.encrypt.view, playground.keys.view, playground.log.view)
        views.forEach { content.addView(it) }
        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        tabs = listOf("Checks", "Sign", "Encrypt", "Keys", "Log").mapIndexed { i, label ->
            val b = Button(this).apply {
                text = label
                isAllCaps = false
                textSize = 13f
                setOnClickListener { select(i) }
            }
            bar.addView(b, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            b to views[i]
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            fitsSystemWindows = true
            addView(content, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
            addView(bar)
        })
        select(0)
        if (savedInstanceState == null) autorun(intent)
    }

    override fun onResume() {
        super.onResume()
        Session.activity = this
    }

    override fun onDestroy() {
        playground.detach()
        super.onDestroy()
    }

    /** Shows tab [index]; the playground tabs read the device again, for a lock screen set meanwhile. */
    private fun select(index: Int) {
        tabs.forEachIndexed { i, (b, v) ->
            v.visibility = if (i == index) View.VISIBLE else View.GONE
            b.isSelected = i == index
            b.alpha = if (i == index) 1f else 0.6f
            b.setTypeface(null, if (i == index) Typeface.BOLD else Typeface.NORMAL)
        }
        playground.log.visible = index == 4
        when (index) {
            1 -> playground.sign.refresh()
            2 -> playground.encrypt.refresh()
            3 -> playground.keys.refresh()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        autorun(intent)
    }

    private fun autorun(intent: Intent?) {
        if (intent?.getBooleanExtra(EXTRA_AUTORUN, false) == true) runChecks()
        if (intent?.getBooleanExtra(EXTRA_PLAYGROUND_DEMO, false) == true) runDemo()
    }

    /** Runs the catalog on the playground's executor: polyjose calls are synchronous and do real work. */
    private fun runChecks() {
        if (running) return
        running = true
        button.isEnabled = false
        output.text = ""
        Session.executor.execute {
            val polyjose = runCatching { version() }.getOrElse { "unavailable (${it.javaClass.simpleName})" }
            val info = listOf(
                "polyjose $polyjose through dev.polyjose:polyjose (${BuildConfig.POLYJOSE_SOURCE}), " +
                    "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) on ${Build.MODEL}",
            )
            runCatalog(info, hasStrongBox(this)) { line ->
                Log.i(TAG, line)
                runOnUiThread { output.append(line + "\n") }
            }
            runOnUiThread {
                running = false
                button.isEnabled = true
            }
        }
    }

    /** The playground's demo walk (run.sh --playground); its lines go to the Checks tab and logcat. */
    private fun runDemo() {
        if (walking) return
        walking = true
        output.text = ""
        DemoWalk(playground) { line ->
            Log.i(TAG, line)
            runOnUiThread { output.append(line + "\n") }
        }.start()
    }

    /**
     * The prompt before a time-bound key's window (PLAYGROUND.md `option.auth.time-bound`): the
     * framework BiometricPrompt with no crypto object, API 28 or later. Only its error code is
     * reported, never its text.
     */
    override fun authenticateNow(deviceCredential: Boolean, done: (ok: Boolean, error: Int?) -> Unit) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            done(false, null)
            return
        }
        val builder = BiometricPrompt.Builder(this)
            .setTitle("polyjose playground")
            .setSubtitle("Authenticate to open the time-bound keys' window")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && deviceCredential) {
            builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        } else {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            builder.setNegativeButton("Cancel", mainExecutor) { _, _ -> done(false, null) }
        }
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = done(true, null)
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = done(false, errorCode)
        }
        try {
            builder.build().authenticate(CancellationSignal(), mainExecutor, callback)
        } catch (t: RuntimeException) {
            done(false, null)
        }
    }

    companion object {
        /** The logcat tag of every result line. */
        const val TAG = "POLYJOSE"

        /** A boolean extra: true starts the run as soon as the activity opens. */
        const val EXTRA_AUTORUN = "autorun"

        /** A boolean extra: true starts the playground's demo walk (run.sh --playground). */
        const val EXTRA_PLAYGROUND_DEMO = "playgroundDemo"
    }
}
