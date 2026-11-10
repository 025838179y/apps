package com.example.facegate;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.concurrent.Executor;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import android.util.Base64;

public class MainActivity extends Activity {
    private static final String PREFS = "face_gate_secure_prefs";
    private static final String KEY_SALT = "pin_salt";
    private static final String KEY_HASH = "pin_hash";
    private static final int PIN_MIN_LENGTH = 6;
    private static final int PBKDF2_ITERATIONS = 160_000;
    private static final int HASH_BITS = 256;

    private android.content.SharedPreferences prefs;
    private LinearLayout root;
    private Executor executor;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        executor = ContextCompat.getMainExecutor(this);
        showLockedScreen();
        if (!hasPin()) {
            setupPinDialog();
        }
    }

    private void showLockedScreen() {
        root = createRoot();
        TextView title = text("Face Gate", 30, true);
        TextView subtitle = text("בחר דרך לאימות כדי להיכנס", 17, false);
        TextView rootInfo = text(rootStatusMessage(), 13, false);
        rootInfo.setPadding(20, 14, 20, 14);

        EditText pinInput = new EditText(this);
        pinInput.setSingleLine(true);
        pinInput.setTextDirection(View.TEXT_DIRECTION_LTR);
        pinInput.setGravity(Gravity.CENTER);
        pinInput.setHint("קוד אישי (לפחות 6 ספרות)");
        pinInput.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        pinInput.setLayoutDirection(View.LAYOUT_DIRECTION_LTR);

        Button pinButton = button("כניסה באמצעות קוד");
        pinButton.setOnClickListener(v -> {
            String pin = pinInput.getText().toString();
            if (!hasPin()) {
                toast("יש להגדיר קוד אישי תחילה");
            } else if (verifyPin(pin)) {
                showUnlockedScreen();
            } else {
                pinInput.setText("");
                toast("הקוד שגוי");
            }
        });

        Button biometricButton = button("אימות ביומטרי (פנים / טביעת אצבע)");
        biometricButton.setOnClickListener(v -> authenticateBiometric());

        Button setupButton = button(hasPin() ? "הגדרת קוד חדש" : "הגדרת קוד אישי");
        setupButton.setOnClickListener(v -> {
            if (hasPin()) {
                askCurrentPinThenChange();
            } else {
                setupPinDialog();
            }
        });

        add(root, title);
        add(root, subtitle);
        add(root, biometricButton);
        add(root, pinInput);
        add(root, pinButton);
        add(root, setupButton);
        add(root, rootInfo);
        setContentView(root);
    }

    private void showUnlockedScreen() {
        root = createRoot();
        TextView title = text("הגישה אושרה", 28, true);
        TextView details = text("האימות הצליח. זהו אזור מוגן לדוגמה בתוך האפליקציה.", 17, false);
        Button lockButton = button("נעילה מחדש");
        lockButton.setOnClickListener(v -> showLockedScreen());
        Button changeButton = button("שינוי הקוד האישי");
        changeButton.setOnClickListener(v -> askCurrentPinThenChange());
        add(root, title);
        add(root, details);
        add(root, changeButton);
        add(root, lockButton);
        setContentView(root);
    }

    private void authenticateBiometric() {
        BiometricManager manager = BiometricManager.from(this);
        int result = manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK);
        if (result != BiometricManager.BIOMETRIC_SUCCESS) {
            toast("אין במכשיר אימות ביומטרי זמין לאפליקציה. אפשר להשתמש בקוד האישי.");
            return;
        }

        BiometricPrompt prompt = new BiometricPrompt(this, executor,
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                        super.onAuthenticationSucceeded(result);
                        showUnlockedScreen();
                    }

                    @Override
                    public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                        super.onAuthenticationError(errorCode, errString);
                        toast("האימות לא הושלם: " + errString);
                    }

                    @Override
                    public void onAuthenticationFailed() {
                        super.onAuthenticationFailed();
                        toast("האימות הביומטרי לא זוהה. אפשר לנסות שוב או להשתמש בקוד.");
                    }
                });

        BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("אימות ל-Face Gate")
                .setSubtitle("השתמש באמצעי האימות הביומטרי שהוגדר במכשיר")
                .setDescription("האימות מתבצע על ידי Android; האפליקציה אינה שומרת תמונת פנים.")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK)
                .setNegativeButtonText("ביטול")
                .build();
        prompt.authenticate(info);
    }

    private void setupPinDialog() {
        LinearLayout fields = new LinearLayout(this);
        fields.setOrientation(LinearLayout.VERTICAL);
        fields.setPadding(28, 8, 28, 0);

        EditText first = pinField("קוד חדש — לפחות 6 ספרות");
        EditText second = pinField("הקלד שוב לאישור");
        fields.addView(first);
        fields.addView(second);

        new AlertDialog.Builder(this)
                .setTitle("הגדרת קוד אישי")
                .setMessage("הקוד נשמר במכשיר כגיבוב עם salt אקראי, ולא כטקסט גלוי.")
                .setView(fields)
                .setCancelable(false)
                .setPositiveButton("שמירה", (dialog, which) -> {
                    String pin = first.getText().toString();
                    String confirm = second.getText().toString();
                    if (pin.length() < PIN_MIN_LENGTH || !pin.matches("[0-9]+")) {
                        toast("הקוד חייב להכיל לפחות 6 ספרות");
                        setupPinDialog();
                    } else if (!pin.equals(confirm)) {
                        toast("הקודים אינם תואמים");
                        setupPinDialog();
                    } else {
                        savePin(pin);
                        toast("הקוד נשמר");
                        showLockedScreen();
                    }
                })
                .setNegativeButton("ביטול", (dialog, which) -> {
                    if (!hasPin()) {
                        toast("כדי להשתמש באפליקציה יש להגדיר קוד אישי");
                        setupPinDialog();
                    }
                })
                .show();
    }

    private void askCurrentPinThenChange() {
        EditText input = pinField("הזן את הקוד הנוכחי");
        new AlertDialog.Builder(this)
                .setTitle("אימות לפני שינוי קוד")
                .setView(input)
                .setPositiveButton("המשך", (dialog, which) -> {
                    if (verifyPin(input.getText().toString())) {
                        setupPinDialog();
                    } else {
                        toast("הקוד הנוכחי שגוי");
                    }
                })
                .setNegativeButton("ביטול", null)
                .show();
    }

    private void savePin(String pin) {
        try {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            byte[] hash = derive(pin.toCharArray(), salt);
            prefs.edit()
                    .putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
                    .putString(KEY_HASH, Base64.encodeToString(hash, Base64.NO_WRAP))
                    .apply();
        } catch (Exception e) {
            toast("לא ניתן לשמור את הקוד במכשיר");
        }
    }

    private boolean verifyPin(String candidate) {
        if (candidate == null || !candidate.matches("[0-9]{" + PIN_MIN_LENGTH + ",}")) return false;
        try {
            String saltText = prefs.getString(KEY_SALT, null);
            String hashText = prefs.getString(KEY_HASH, null);
            if (saltText == null || hashText == null) return false;
            byte[] salt = Base64.decode(saltText, Base64.NO_WRAP);
            byte[] expected = Base64.decode(hashText, Base64.NO_WRAP);
            byte[] actual = derive(candidate.toCharArray(), salt);
            return MessageDigest.isEqual(expected, actual);
        } catch (Exception e) {
            return false;
        }
    }

    private byte[] derive(char[] pin, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(pin, salt, PBKDF2_ITERATIONS, HASH_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
            java.util.Arrays.fill(pin, '\0');
        }
    }

    private boolean hasPin() {
        return prefs.contains(KEY_SALT) && prefs.contains(KEY_HASH);
    }

    private EditText pinField(String hint) {
        EditText edit = new EditText(this);
        edit.setHint(hint);
        edit.setSingleLine(true);
        edit.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        edit.setTextDirection(View.TEXT_DIRECTION_LTR);
        edit.setGravity(Gravity.CENTER);
        return edit;
    }

    private LinearLayout createRoot() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setGravity(Gravity.CENTER);
        layout.setPadding(28, 36, 28, 36);
        layout.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
        layout.setBackgroundColor(0xFFF5F6FA);
        return layout;
    }

    private TextView text(String value, int size, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(0xFF172033);
        view.setGravity(Gravity.CENTER);
        view.setPadding(8, 12, 8, 12);
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }

    private Button button(String label) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setTextSize(16);
        return button;
    }

    private void add(LinearLayout parent, View child) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.setMargins(0, 8, 0, 8);
        parent.addView(child, params);
    }

    private String rootStatusMessage() {
        boolean rooted = Build.TAGS != null && Build.TAGS.contains("test-keys");
        String[] paths = {
                "/system/bin/su", "/system/xbin/su", "/sbin/su",
                "/system/app/Superuser.apk", "/data/adb/magisk"
        };
        for (String path : paths) {
            if (new java.io.File(path).exists()) rooted = true;
        }
        if (rooted) {
            return "זוהו סימנים אפשריים ל-Root. Root אינו הופך אפליקציה רגילה לשיטת נעילה של Android; לשם כך נדרשת תמיכה ברמת ROM/מערכת.";
        }
        return "לא זוהו סימני Root נפוצים. בדיקה זו אינה ודאית ואינה משפיעה על האימות.";
    }

    private void toast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }
}
