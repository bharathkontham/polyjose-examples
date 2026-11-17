// The playground's shared state and its one background executor. Every polyjose call of the app
// (the checks, every tab, the demo walk) runs on [Session.executor], never on the main thread:
// a key with user authentication blocks its thread while the system prompt is up, and
// `BiometricPromptAuthorizer` refuses the main thread.
package dev.polyjose.examples.playground

import android.app.Activity
import android.os.Build
import dev.polyjose.BiometricPromptAuthorizer
import dev.polyjose.version
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** For the whole process: it outlives an activity that is recreated. */
object Session {
    val executor: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, "polyjose").apply { isDaemon = true } }
    val log = PlaygroundLog()

    /** The activity a per-use prompt is shown from. */
    @Volatile var activity: Activity? = null

    val engine = Engine(log) { deviceCredential, subtitle ->
        BiometricPromptAuthorizer(activity ?: throw IllegalStateException(), "polyjose playground", "Cancel", deviceCredential, subtitle)
    }

    private val deviceLogged = AtomicBoolean(false)

    /** Tap 0, the `device` line: once per process. */
    fun logDevice(device: DeviceInfo) {
        if (!deviceLogged.compareAndSet(false, true)) return
        executor.execute {
            val polyjose = try { version() } catch (t: Throwable) { "unavailable" }
            log.device(
                listOf(
                    Field.id("polyjose", polyjose),
                    Field.id("os", "android-${device.release}"),
                    Field.id("model", device.model),
                    Field.bool("emulator", device.emulator),
                    Field.num("api", device.api.toLong()),
                    Field.bool("strongbox", device.hasStrongBox),
                    Field.bool("lock-screen", device.lockScreen),
                ),
            )
        }
    }
}

/** The time-bound key's prompt: the activity shows the framework `BiometricPrompt` (no key, no crypto object). */
fun interface PromptHost {
    /** Shows the prompt; [done] gets whether the user authenticated and the framework's error code, on the main thread. */
    fun authenticateNow(deviceCredential: Boolean, done: (ok: Boolean, error: Int?) -> Unit)
}

/** The four playground tabs of one activity. */
class Playground(val activity: Activity, private val host: PromptHost) {
    val ui = Ui(activity)
    val sign = OperationTab(this, Kind.Sign)
    val encrypt = OperationTab(this, Kind.Encrypt)
    val keys = KeysTab(this)
    val log = LogTab(this)

    init {
        Session.activity = activity
        Session.logDevice(device())
    }

    fun device(): DeviceInfo = DeviceInfo.read(activity)

    /** From the activity's `onDestroy`: the session drops what points at this activity, and only that. */
    fun detach() {
        if (Session.activity === activity) Session.activity = null
        log.detach()
    }

    /** Runs [work] on the executor and [done] with its value on the main thread. */
    fun <T> background(work: () -> T, done: (T) -> Unit) {
        Session.executor.execute {
            val value = work()
            activity.runOnUiThread { done(value) }
        }
    }

    /** One tap of a Sign or Encrypt button: the engine on the executor, the result on the card. */
    fun submit(req: Request, card: ResultCard, after: (Result) -> Unit) {
        card.running(req.failure?.label ?: req.action?.label ?: "Run")
        val device = device()
        background({ Session.engine.perform(req, device) }) { r ->
            card.show(r)
            after(r)
            keys.refresh()
        }
    }

    /** **Authenticate now**, for time-bound keys: a tap of its own, logged as one. */
    fun authenticateNow(sel: Selection) {
        val device = device()
        val dc = Matrix.deviceCredential(sel.auth, device)
        val tap = Session.log.begin("Authenticate now · ${sel.storeLabel}")
        tap.input(listOf(Field.id("op", "authenticate"), Field.id("store", sel.store.id), Field.id("alg", sel.alg), Field.id("auth", sel.auth.id), Field.bool("device-credential", dc)))
        tap.note("option.auth.time-bound")
        if (Build.VERSION.SDK_INT < Matrix.PROMPT_API) {
            tap.authenticate(false, 0, null)
            return
        }
        val t0 = now()
        host.authenticateNow(dc) { ok, error -> tap.authenticate(ok, now() - t0, error) }
    }

    fun refreshAll() {
        sign.refresh()
        encrypt.refresh()
        keys.refresh()
        log.refresh()
    }
}
