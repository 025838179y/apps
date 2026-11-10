from pathlib import Path
import sys

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent / "UniversalAuth"

def read(path):
    return (ROOT / path).read_text(encoding="utf-8")

def write(path, value):
    p = ROOT / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(value, encoding="utf-8")

# PBKDF2 hashes with per-credential salt. No PIN/pattern is stored as plaintext.
write("faceunlock/src/main/java/ax/nd/faceunlock/pref/CredentialStore.kt", r'''package ax.nd.faceunlock.pref

import android.content.Context
import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

object CredentialStore {
    private const val PREFS = "face_unlock_extra_credentials"
    private const val ITERATIONS = 180_000
    private const val KEY_BITS = 256
    private const val PIN_SALT = "pin_salt"
    private const val PIN_HASH = "pin_hash"
    private const val PATTERN_SALT = "pattern_salt"
    private const val PATTERN_HASH = "pattern_hash"
    private const val FAILURES = "failed_attempts"
    private const val LOCK_UNTIL = "lock_until"

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    fun hasPin(context: Context) = prefs(context).contains(PIN_HASH)
    fun hasPattern(context: Context) = prefs(context).contains(PATTERN_HASH)
    fun hasAny(context: Context) = hasPin(context) || hasPattern(context)
    fun savePin(context: Context, pin: String) = save(context, PIN_SALT, PIN_HASH, pin)
    fun savePattern(context: Context, pattern: String) = save(context, PATTERN_SALT, PATTERN_HASH, pattern)
    fun verifyPin(context: Context, pin: String) = verify(context, PIN_SALT, PIN_HASH, pin)
    fun verifyPattern(context: Context, pattern: String) = verify(context, PATTERN_SALT, PATTERN_HASH, pattern)

    fun clear(context: Context) {
        prefs(context).edit().remove(PIN_SALT).remove(PIN_HASH)
            .remove(PATTERN_SALT).remove(PATTERN_HASH).apply()
    }

    fun isLockedOut(context: Context): Boolean =
        System.currentTimeMillis() < prefs(context).getLong(LOCK_UNTIL, 0L)

    fun lockoutRemainingSeconds(context: Context): Long =
        ((prefs(context).getLong(LOCK_UNTIL, 0L) - System.currentTimeMillis()).coerceAtLeast(0L) + 999L) / 1000L

    fun recordFailure(context: Context) {
        val p = prefs(context)
        val count = p.getInt(FAILURES, 0) + 1
        if (count >= 5) {
            p.edit().putInt(FAILURES, 0)
                .putLong(LOCK_UNTIL, System.currentTimeMillis() + 30_000L).apply()
        } else {
            p.edit().putInt(FAILURES, count).apply()
        }
    }

    fun recordSuccess(context: Context) {
        prefs(context).edit().putInt(FAILURES, 0).putLong(LOCK_UNTIL, 0L).apply()
    }

    private fun save(context: Context, saltKey: String, hashKey: String, value: String) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val hash = derive(value.toCharArray(), salt)
        prefs(context).edit()
            .putString(saltKey, Base64.encodeToString(salt, Base64.NO_WRAP))
            .putString(hashKey, Base64.encodeToString(hash, Base64.NO_WRAP))
            .apply()
    }

    private fun verify(context: Context, saltKey: String, hashKey: String, value: String): Boolean {
        val p = prefs(context)
        val saltText = p.getString(saltKey, null) ?: return false
        val expectedText = p.getString(hashKey, null) ?: return false
        return try {
            val salt = Base64.decode(saltText, Base64.NO_WRAP)
            val expected = Base64.decode(expectedText, Base64.NO_WRAP)
            MessageDigest.isEqual(expected, derive(value.toCharArray(), salt))
        } catch (_: Exception) {
            false
        }
    }

    private fun derive(chars: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(chars, salt, ITERATIONS, KEY_BITS)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
            chars.fill('\u0000')
        }
    }
}
''')

# Reusable 3x3 pattern capture view.
write("faceunlock/src/main/java/ax/nd/faceunlock/PatternGridView.kt", r'''package ax.nd.faceunlock

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.View
import kotlin.math.abs
import kotlin.math.hypot

class PatternGridView @JvmOverloads constructor(context: Context, attrs: AttributeSet? = null) : View(context, attrs) {
    private val selected = mutableListOf<Int>()
    private val path = Path()
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private var pointerX = -1f
    private var pointerY = -1f
    var onPatternComplete: ((String) -> Unit)? = null

    private fun cellSize(): Float = (minOf(width, height).toFloat() * 0.72f) / 2f
    private fun center(index: Int): Pair<Float, Float> {
        val spacing = cellSize()
        return Pair(width / 2f - spacing + (index % 3) * spacing,
            height / 2f - spacing + (index / 3) * spacing)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val radius = (cellSize() * 0.12f).coerceAtLeast(8f)
        if (selected.isNotEmpty()) {
            path.reset()
            selected.forEachIndexed { i, index ->
                val (x, y) = center(index)
                if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
            }
            if (pointerX >= 0f && pointerY >= 0f) path.lineTo(pointerX, pointerY)
            paint.color = 0xFF4B78C2.toInt()
            paint.style = Paint.Style.STROKE
            paint.strokeWidth = radius * 0.45f
            paint.strokeCap = Paint.Cap.ROUND
            paint.strokeJoin = Paint.Join.ROUND
            canvas.drawPath(path, paint)
        }
        for (i in 0..8) {
            val (x, y) = center(i)
            paint.style = Paint.Style.FILL
            paint.color = if (i in selected) 0xFF4B78C2.toInt() else 0xFF9AA4B2.toInt()
            canvas.drawCircle(x, y, radius, paint)
            if (i in selected) {
                paint.color = 0xFFFFFFFF.toInt()
                canvas.drawCircle(x, y, radius * 0.34f, paint)
            }
        }
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        when (event.action) {
            MotionEvent.ACTION_DOWN -> {
                resetPattern()
                pointerX = event.x
                pointerY = event.y
                addHit(event.x, event.y)
                invalidate()
                return true
            }
            MotionEvent.ACTION_MOVE -> {
                pointerX = event.x
                pointerY = event.y
                addHit(event.x, event.y)
                invalidate()
                return true
            }
            MotionEvent.ACTION_UP -> {
                pointerX = -1f
                pointerY = -1f
                invalidate()
                if (selected.size >= 4) onPatternComplete?.invoke(pattern())
                return true
            }
            MotionEvent.ACTION_CANCEL -> {
                resetPattern()
                return true
            }
        }
        return true
    }

    private fun addHit(x: Float, y: Float) {
        var hit = -1
        val threshold = (cellSize() * 0.38f).coerceAtLeast(20f)
        for (i in 0..8) {
            val (cx, cy) = center(i)
            if (hypot((x - cx).toDouble(), (y - cy).toDouble()) < threshold) {
                hit = i
                break
            }
        }
        if (hit < 0 || hit in selected) return
        if (selected.isNotEmpty()) {
            val last = selected.last()
            val x1 = last % 3
            val y1 = last / 3
            val x2 = hit % 3
            val y2 = hit / 3
            val dx = x2 - x1
            val dy = y2 - y1
            if ((abs(dx) == 2 && dy == 0) || (dx == 0 && abs(dy) == 2) || (abs(dx) == 2 && abs(dy) == 2)) {
                val middle = (x1 + dx / 2) + (y1 + dy / 2) * 3
                if (middle !in selected) selected.add(middle)
            }
        }
        selected.add(hit)
    }

    fun pattern(): String = selected.joinToString("-")
    fun resetPattern() {
        selected.clear()
        pointerX = -1f
        pointerY = -1f
        invalidate()
    }
}
''')

# Credential enrollment UI.
write("faceunlock/src/main/java/ax/nd/faceunlock/CredentialSetupActivity.kt", r'''package ax.nd.faceunlock

import android.app.AlertDialog
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import ax.nd.faceunlock.pref.CredentialStore

class CredentialSetupActivity : AppCompatActivity() {
    private lateinit var pinStatus: TextView
    private lateinit var patternStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(28, 32, 28, 32)
            setBackgroundColor(0xFFF4F6FA.toInt())
        }
        root.addView(TextView(this).apply {
            text = "קוד נוסף לנעילת המסך"
            textSize = 24f
            gravity = Gravity.CENTER
        }, lp())
        root.addView(TextView(this).apply {
            text = "אפשר להגדיר קוד ספרות, דפוס, או את שניהם. זיהוי הפנים ימשיך לפעול במקביל."
            textSize = 15f
            gravity = Gravity.CENTER
        }, lp())
        pinStatus = statusView()
        patternStatus = statusView()
        root.addView(pinStatus, lp())
        root.addView(makeButton("הגדרת קוד ספרות", ::setupPin), lp())
        root.addView(patternStatus, lp())
        root.addView(makeButton("הגדרת דפוס", ::setupPattern), lp())
        root.addView(makeButton("מחיקת הקודים הנוספים", ::clearCredentials), lp())
        root.addView(makeButton("סיום", { finish() }), lp())
        setContentView(root)
        updateStatus()
    }

    private fun setupPin() {
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 8, 24, 0) }
        val first = EditText(this).apply {
            hint = "קוד ספרות — לפחות 6 ספרות"
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
        }
        val second = EditText(this).apply {
            hint = "הקלד שוב לאישור"
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
        }
        box.addView(first)
        box.addView(second)
        val dialog = AlertDialog.Builder(this).setTitle("הגדרת קוד ספרות")
            .setView(box).setPositiveButton("שמירה", null).setNegativeButton("ביטול", null).create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val pin = first.text.toString()
                if (pin.length < 6 || !pin.all { it in '0'..'9' }) {
                    first.error = "יש להזין לפחות 6 ספרות"
                } else if (pin != second.text.toString()) {
                    second.error = "הקודים אינם תואמים"
                } else {
                    CredentialStore.savePin(this, pin)
                    Toast.makeText(this, "קוד הספרות נשמר", Toast.LENGTH_SHORT).show()
                    dialog.dismiss()
                    updateStatus()
                }
            }
        }
        dialog.show()
    }

    private fun setupPattern() {
        capturePattern("צייר דפוס חדש") { first ->
            capturePattern("צייר שוב לאישור") { second ->
                if (first == second) {
                    CredentialStore.savePattern(this, first)
                    Toast.makeText(this, "הדפוס נשמר", Toast.LENGTH_SHORT).show()
                    updateStatus()
                } else {
                    Toast.makeText(this, "הדפוסים אינם תואמים. נסה שוב.", Toast.LENGTH_LONG).show()
                    setupPattern()
                }
            }
        }
    }

    private fun capturePattern(title: String, result: (String) -> Unit) {
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(20, 12, 20, 12)
        }
        val hint = TextView(this).apply {
            text = "העבר את האצבע בין לפחות ארבע נקודות"
            gravity = Gravity.CENTER
        }
        val grid = PatternGridView(this)
        grid.onPatternComplete = { value -> hint.text = "דפוס נקלט (${value.split("-").size} נקודות)" }
        content.addView(hint, lp())
        content.addView(grid, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(300)))
        val dialog = AlertDialog.Builder(this).setTitle(title).setView(content)
            .setPositiveButton("המשך", null).setNegativeButton("ביטול", null).create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val value = grid.pattern()
                if (value.split("-").size >= 4) {
                    dialog.dismiss()
                    result(value)
                } else {
                    hint.text = "יש לחבר לפחות ארבע נקודות שונות"
                }
            }
        }
        dialog.show()
    }

    private fun clearCredentials() {
        AlertDialog.Builder(this).setTitle("מחיקת הקודים")
            .setMessage("למחוק את קוד הספרות ואת הדפוס שהוגדרו באפליקציה?")
            .setPositiveButton("מחיקה") { _, _ ->
                CredentialStore.clear(this)
                updateStatus()
            }.setNegativeButton("ביטול", null).show()
    }

    private fun updateStatus() {
        pinStatus.text = if (CredentialStore.hasPin(this)) "קוד ספרות: מוגדר" else "קוד ספרות: לא הוגדר"
        patternStatus.text = if (CredentialStore.hasPattern(this)) "דפוס: מוגדר" else "דפוס: לא הוגדר"
    }

    private fun statusView() = TextView(this).apply { textSize = 15f; gravity = Gravity.CENTER }
    private fun makeButton(label: String, action: () -> Unit) = Button(this).apply {
        text = label
        isAllCaps = false
        setOnClickListener { action() }
    }
    private fun lp() = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
        setMargins(0, dp(7), 0, dp(7))
    }
    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
}
''')

# Lock-screen overlay: local PIN keypad and 3x3 pattern, with attempt throttling.
write("faceunlock/src/main/java/ax/nd/faceunlock/service/LockscreenCredentialOverlay.kt", r'''package ax.nd.faceunlock.service

import android.content.Context
import android.graphics.Color
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.GridLayout
import android.widget.LinearLayout
import android.widget.TextView
import ax.nd.faceunlock.PatternGridView
import ax.nd.faceunlock.pref.CredentialStore

class LockscreenCredentialOverlay(private val context: Context, private val onAuthenticated: () -> Unit) {
    val view: View
    private val message: TextView
    private val pinDisplay: TextView
    private val pinPanel: LinearLayout
    private val patternPanel: LinearLayout
    private val patternGrid: PatternGridView
    private val pinBuffer = StringBuilder()
    private var mode = if (CredentialStore.hasPin(context)) MODE_PIN else MODE_PATTERN

    init {
        val root = LinearLayout(context).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(dp(26), dp(28), dp(26), dp(28))
            setBackgroundColor(Color.WHITE)
        }
        root.addView(TextView(context).apply {
            text = "אימות נוסף"
            textSize = 26f
            setTextColor(Color.rgb(25, 35, 55))
            gravity = Gravity.CENTER
        }, lp())
        message = TextView(context).apply {
            text = "אפשר לאמת באמצעות קוד ספרות או דפוס"
            textSize = 15f
            gravity = Gravity.CENTER
            setTextColor(Color.DKGRAY)
        }
        root.addView(message, lp())

        if (CredentialStore.hasPin(context) && CredentialStore.hasPattern(context)) {
            val tabs = LinearLayout(context).apply { gravity = Gravity.CENTER }
            tabs.addView(button("קוד ספרות") { showMode(MODE_PIN) }, weightLp())
            tabs.addView(button("דפוס") { showMode(MODE_PATTERN) }, weightLp())
            root.addView(tabs, lp())
        }

        pinPanel = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER }
        pinDisplay = TextView(context).apply {
            textSize = 28f
            gravity = Gravity.CENTER
            setTextColor(Color.DKGRAY)
            text = ""
        }
        pinPanel.addView(pinDisplay, lp())
        val keypad = GridLayout(context).apply { columnCount = 3; rowCount = 4 }
        listOf("1", "2", "3", "4", "5", "6", "7", "8", "9", "⌫", "0", "אישור").forEach { digit ->
            keypad.addView(button(digit) {
                when (digit) {
                    "⌫" -> if (pinBuffer.isNotEmpty()) pinBuffer.deleteCharAt(pinBuffer.lastIndex)
                    "אישור" -> checkPin()
                    else -> if (pinBuffer.length < 12) pinBuffer.append(digit)
                }
                updatePinDisplay()
            }, GridLayout.LayoutParams().apply {
                width = dp(86)
                height = dp(58)
                setMargins(dp(4), dp(4), dp(4), dp(4))
            })
        }
        pinPanel.addView(keypad)

        patternPanel = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER }
        patternGrid = PatternGridView(context).apply { minimumHeight = dp(310) }
        patternGrid.onPatternComplete = { value -> checkPattern(value); patternGrid.resetPattern() }
        patternPanel.addView(TextView(context).apply {
            text = "צייר את הדפוס שהגדרת"
            gravity = Gravity.CENTER
            textSize = 16f
            setTextColor(Color.DKGRAY)
        }, lp())
        patternPanel.addView(patternGrid, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(310)))

        root.addView(pinPanel, lp())
        root.addView(patternPanel, lp())
        view = root
        showMode(mode)
    }

    fun showFaceFailure() {
        message.text = "זיהוי הפנים לא הצליח. אפשר להמשיך באמצעות קוד ספרות או דפוס."
    }

    private fun showMode(next: Int) {
        mode = next
        pinBuffer.clear()
        updatePinDisplay()
        pinPanel.visibility = if (mode == MODE_PIN && CredentialStore.hasPin(context)) View.VISIBLE else View.GONE
        patternPanel.visibility = if (mode == MODE_PATTERN && CredentialStore.hasPattern(context)) View.VISIBLE else View.GONE
        message.text = if (CredentialStore.isLockedOut(context)) {
            "נחסם זמנית. נסה שוב בעוד ${CredentialStore.lockoutRemainingSeconds(context)} שניות."
        } else "הזן את הקוד הנוסף כדי להמשיך"
    }

    private fun checkPin() {
        if (blocked()) return
        if (CredentialStore.verifyPin(context, pinBuffer.toString())) succeed() else fail()
    }

    private fun checkPattern(pattern: String) {
        if (blocked()) return
        if (CredentialStore.verifyPattern(context, pattern)) succeed() else fail()
    }

    private fun blocked(): Boolean {
        if (!CredentialStore.isLockedOut(context)) return false
        message.text = "נחסם זמנית. נסה שוב בעוד ${CredentialStore.lockoutRemainingSeconds(context)} שניות."
        return true
    }

    private fun fail() {
        CredentialStore.recordFailure(context)
        pinBuffer.clear()
        updatePinDisplay()
        message.text = if (CredentialStore.isLockedOut(context)) {
            "יותר מדי ניסיונות. המתן 30 שניות."
        } else "הקוד שגוי. נסה שוב."
    }

    private fun succeed() {
        CredentialStore.recordSuccess(context)
        onAuthenticated()
    }

    private fun updatePinDisplay() { pinDisplay.text = "•".repeat(pinBuffer.length) }
    private fun button(label: String, click: () -> Unit) = Button(context).apply {
        text = label
        isAllCaps = false
        setOnClickListener { click() }
    }
    private fun lp() = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
        setMargins(0, dp(5), 0, dp(5))
    }
    private fun weightLp() = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
        setMargins(dp(4), dp(4), dp(4), dp(4))
    }
    private fun dp(value: Int) = (value * context.resources.displayMetrics.density).toInt()

    companion object {
        private const val MODE_PIN = 1
        private const val MODE_PATTERN = 2
    }
}
''')

# Add controls to the existing original MainActivity.
main_path = "faceunlock/src/main/java/ax/nd/faceunlock/MainActivity.kt"
main = read(main_path)
if "binding.credentialsBtn" not in main:
    main = main.replace(
        "import kotlinx.coroutines.launch\n",
        "import kotlinx.coroutines.launch\nimport kotlinx.coroutines.Dispatchers\nimport kotlinx.coroutines.withContext\n"
    )
    anchor = '''        binding.authBtn.setOnClickListener {
            startActivity(Intent(this, FaceAuthActivity::class.java))
        }
'''
    injected = anchor + '''
        binding.credentialsBtn.setOnClickListener {
            startActivity(Intent(this, CredentialSetupActivity::class.java))
        }
        binding.rootBtn.setOnClickListener { requestMagiskRoot() }
        binding.lockSettingsBtn.setOnClickListener {
            MaterialDialog(this).show {
                title(text = "הגדרות מסך הנעילה")
                message(text = "כדי שהאפליקציה תציג אימות מעל מסך הנעילה, יש להפעיל את שירות הנגישות שלה. Android אינו מאפשר לאפליקציה רגילה להחליף את מנגנון נעילת המערכת מתוך ההגדרות.")
                positiveButton(text = "פתיחת הגדרות נגישות") {
                    startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                }
                negativeButton(text = "ביטול") { }
            }
        }
'''
    if anchor not in main:
        raise SystemExit("Cannot patch MainActivity click handlers")
    main = main.replace(anchor, injected, 1)
    marker = '''    // Called once all libs are valid
    fun checkAndAskForPermissions() {
'''
    method = '''    private fun requestMagiskRoot() {
        lifecycleScope.launch {
            val granted = withContext(Dispatchers.IO) {
                try {
                    val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
                    val output = process.inputStream.bufferedReader().use { it.readText() }
                    process.waitFor() == 0 && output.contains("uid=0")
                } catch (_: Exception) {
                    false
                }
            }
            Toast.makeText(
                this@MainActivity,
                if (granted) "הרשאת Root אושרה דרך מנהל SU" else "לא אושרה הרשאת Root. ודא ש-Magisk מותקן ונסה שוב.",
                Toast.LENGTH_LONG
            ).show()
        }
    }

'''
    if marker not in main:
        raise SystemExit("Cannot find MainActivity insertion point")
    main = main.replace(marker, method + marker, 1)
    write(main_path, main)

# Add PIN/pattern, Magisk and lock-screen settings buttons to the original screen.
layout_path = "faceunlock/src/main/res/layout/activity_main2.xml"
layout = read(layout_path)
if "credentials_btn" not in layout:
    layout = layout.replace(
'''    <androidx.fragment.app.FragmentContainerView
''',
'''    <Button
        android:id="@+id/credentials_btn"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginTop="8dp"
        android:text="PIN / Pattern"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toBottomOf="@+id/remove_btn" />

    <Button
        android:id="@+id/root_btn"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginTop="8dp"
        android:text="בקשת Root מ-Magisk"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toBottomOf="@+id/credentials_btn" />

    <Button
        android:id="@+id/lock_settings_btn"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_marginTop="8dp"
        android:text="הגדרות מסך הנעילה"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toBottomOf="@+id/root_btn" />

    <androidx.fragment.app.FragmentContainerView
''',1)
    layout = layout.replace('app:layout_constraintTop_toBottomOf="@+id/remove_btn" />', 'app:layout_constraintTop_toBottomOf="@+id/lock_settings_btn" />', 1)
    write(layout_path, layout)

# Register the credential setup activity in the original manifest.
manifest_path = "faceunlock/src/main/AndroidManifest.xml"
manifest = read(manifest_path)
if "CredentialSetupActivity" not in manifest:
    anchor = '''        <activity
            android:name=".FaceAuthActivity"
'''
    entry = '''        <activity
            android:name=".CredentialSetupActivity"
            android:exported="false"
            android:label="PIN / Pattern"
            android:theme="@style/SettingsTheme" />
'''
    if anchor not in manifest:
        raise SystemExit("Cannot patch AndroidManifest")
    manifest = manifest.replace(anchor, entry + anchor, 1)
    write(manifest_path, manifest)

# Show the extra credential UI in the existing lock-screen accessibility service.
service_path = "faceunlock/src/main/java/ax/nd/faceunlock/service/LockscreenFaceAuthService.kt"
service = read(service_path)
if "LockscreenCredentialOverlay" not in service:
    service = service.replace(
        "import android.view.WindowManager\n",
        "import android.view.WindowManager\nimport android.view.ViewGroup\n"
    )
    service = service.replace(
        "import ax.nd.faceunlock.pref.Prefs\n",
        "import ax.nd.faceunlock.pref.Prefs\nimport ax.nd.faceunlock.pref.CredentialStore\n"
    )
    service = service.replace(
        "    private var textViewAnimator: ViewPropertyAnimator? = null\n",
        "    private var textViewAnimator: ViewPropertyAnimator? = null\n    private var credentialOverlay: LockscreenCredentialOverlay? = null\n"
    )
    old_show = '''    private fun show() {
        if(!active) {
            if(Util.isFaceUnlockEnrolled(this)) {
                active = true
                // If animation is currently playing, we need to fire it's end listener
                if(showStatusText) {
                    textViewAnimator?.cancel()
                    textView?.text = "Looking for face..."
                    windowManager?.addView(textView, params)
                }
                startTime = System.currentTimeMillis()
                controller?.start()
            }
        }
    }
'''
    new_show = '''    private fun show() {
        if (!active) {
            val faceEnrolled = Util.isFaceUnlockEnrolled(this)
            val credentialsConfigured = CredentialStore.hasAny(this)
            if (faceEnrolled || credentialsConfigured) {
                active = true
                if (showStatusText && !credentialsConfigured) {
                    textViewAnimator?.cancel()
                    textView?.text = "Looking for face..."
                    windowManager?.addView(textView, params)
                }
                startTime = System.currentTimeMillis()
                if (faceEnrolled) controller?.start()
                if (credentialsConfigured) showCredentialOverlay()
            }
        }
    }

    private fun showCredentialOverlay() {
        if (credentialOverlay != null) return
        val overlay = LockscreenCredentialOverlay(this) { onAuthed() }
        val overlayParams = WindowManager.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN
                    or WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED,
            PixelFormat.TRANSLUCENT
        ).apply { gravity = Gravity.CENTER }
        credentialOverlay = overlay
        try {
            windowManager?.addView(overlay.view, overlayParams)
        } catch (e: Exception) {
            Log.e(TAG, "Could not display PIN/pattern overlay", e)
            credentialOverlay = null
        }
    }

    private fun removeCredentialOverlay() {
        val overlay = credentialOverlay ?: return
        try { windowManager?.removeView(overlay.view) } catch (_: Exception) { }
        credentialOverlay = null
    }
'''
    if old_show not in service:
        raise SystemExit("Cannot patch LockscreenFaceAuthService.show")
    service = service.replace(old_show, new_show, 1)
    service = service.replace(
        '''    private fun hide(delay: Int = 0) {
        if(active) {
            active = false
''',
        '''    private fun hide(delay: Int = 0) {
        if(active) {
            active = false
            removeCredentialOverlay()
''',1
    )
    service = service.replace(
        '''        unregisterLockStateReceiver()
        unregisterUnlockReceiver()
        hide()
''',
        '''        unregisterLockStateReceiver()
        unregisterUnlockReceiver()
        removeCredentialOverlay()
        hide()
''',1
    )
    service = service.replace(
        '''    private fun removeTextViewFromWindowManager() {
        windowManager?.removeView(textView)
    }
''',
        '''    private fun removeTextViewFromWindowManager() {
        try {
            if (textView?.parent != null) windowManager?.removeView(textView)
        } catch (_: Exception) { }
    }
''',1
    )
    import re
    service, n = re.subn(
        r"    override fun onAuthed\(\) \{.*?\n    \}\n\n    override fun onError",
        '''    override fun onAuthed() {
        Log.d("MeasureFaceUnlock", "Total time: " + (System.currentTimeMillis() - startTime))
        val unlockAnimation = when(FaceApplication.getApp().prefs.unlockAnimation.get()) {
            "mode_wake_and_unlock" -> XposedConstants.MODE_WAKE_AND_UNLOCK
            "mode_wake_and_unlock_pulsing" -> XposedConstants.MODE_WAKE_AND_UNLOCK_PULSING
            else -> XposedConstants.MODE_UNLOCK_FADING
        }
        sendBroadcast(Intent(XposedConstants.ACTION_UNLOCK_DEVICE).apply {
            putExtra(XposedConstants.EXTRA_UNLOCK_MODE, unlockAnimation)
            putExtra(XposedConstants.EXTRA_BYPASS_KEYGUARD, prefs.bypassKeyguard.get())
        })
        handler?.post {
            if (credentialOverlay != null) {
                hide()
            } else {
                textView?.text = "Welcome!"
                hide(delay = 1000)
            }
        }
    }

    override fun onError''',
        service,
        count=1,
        flags=re.S
    )
    if n != 1:
        raise SystemExit("Cannot patch LockscreenFaceAuthService.onAuthed")
    service = service.replace(
        "val faceEnrolled = Util.isFaceUnlockEnrolled(this)",
        "val faceEnrolled = LibManager.libsLoaded.get() && Util.isFaceUnlockEnrolled(this)",
        1
    )
    old_connected = '''    override fun onServiceConnected() {
        super.onServiceConnected()

        if(!LibManager.libsLoaded.get()) {
            // Libs not loaded, abort
            Log.w(TAG, "Libs not loaded, disabling self...")
            disableSelf() // This doesn't work in onCreate
            return
        }
    }
'''
    new_connected = '''    override fun onServiceConnected() {
        super.onServiceConnected()

        if(!LibManager.libsLoaded.get() && !CredentialStore.hasAny(this)) {
            // The face engine is unavailable and no local PIN/pattern has been configured.
            Log.w(TAG, "Face libraries and local credentials are unavailable, disabling self...")
            disableSelf()
            return
        }
    }
'''
    service = service.replace(old_connected, new_connected, 1)
    service = service.replace(
        '''    override fun onError(errId: Int, message: String) {
        handler?.post {
            textView?.text = message
            hide(delay = 2000)
        }
    }
''',
        '''    override fun onError(errId: Int, message: String) {
        handler?.post {
            if (credentialOverlay != null) {
                credentialOverlay?.showFaceFailure()
            } else {
                textView?.text = message
                hide(delay = 2000)
            }
        }
    }
''',
        1
    )
    write(service_path, service)

# Keep upstream notices and document the patch.
write("NOTICE-MODIFICATIONS.txt",
      "Modified in 2026: added optional PIN/pattern fallback, Magisk SU permission test, and settings shortcut.\\n" +
      "Original UniversalAuth source is covered by LICENSE.md.\\n")
readme = read("README.md")
readme += """

## PIN / pattern extension
This build adds optional PIN and 3x3 pattern authentication in the existing accessibility lock-screen overlay. Credentials are stored as salted PBKDF2-HMAC-SHA256 hashes; five failed attempts trigger a 30-second lockout. A button runs su -c id to request Magisk superuser permission. Another button opens Android Accessibility settings.

Android does not provide a general public setting that lets a third-party app register itself as the system Keyguard. The settings shortcut opens the accessibility service settings required by this project; its existing Xposed/LSPosed integration remains necessary for the system-unlock flow. The Magisk button only requests/checks SU permission and does not replace Android's native lockscreen.
"""
write("README.md", readme)
print("Patched original UniversalAuth source successfully")
