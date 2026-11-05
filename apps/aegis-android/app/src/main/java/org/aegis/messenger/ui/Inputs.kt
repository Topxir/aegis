package org.aegis.messenger.ui

import android.content.Context
import android.graphics.Color as AColor
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.util.TypedValue
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.res.ResourcesCompat
import org.aegis.messenger.R

/**
 * Text input for free text. Compose 1.6 cannot set IME_FLAG_NO_PERSONALIZED_LEARNING,
 * so message, search and profile text use a platform EditText with the flag set.
 */
@Composable
fun ImeText(
    value: String,
    onChange: (String) -> Unit,
    hint: String,
    modifier: Modifier = Modifier,
    maxLines: Int = 5,
    maxChars: Int = Int.MAX_VALUE,
    search: Boolean = false,
    autoFocus: Boolean = false,
    enabled: Boolean = true,
    password: Boolean = false,
    single: Boolean = false,
    mono: Boolean = false,
    uri: Boolean = false,
    ascii: Boolean = false,
    onSubmit: () -> Unit = {},
) {
    val change by rememberUpdatedState(onChange)
    val submit by rememberUpdatedState(onSubmit)
    AndroidView(
        modifier = modifier,
        factory = { ctx ->
            EditText(ctx).apply {
                background = null
                setTextColor(Ui.text.toArgb())
                setHintTextColor(Ui.muted.toArgb())
                highlightColor = AColor.argb(80, 233, 233, 236)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
                ResourcesCompat.getFont(ctx, if (mono) R.font.geist_mono_regular else R.font.geist_regular)?.let { typeface = it }
                val pad = (10 * ctx.resources.displayMetrics.density).toInt()
                setPadding(0, pad, 0, pad)
                this.hint = hint
                isEnabled = enabled
                var type = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                if (password) {
                    setSingleLine(true)
                    type = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                    imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_FLAG_NO_EXTRACT_UI
                } else if (single || search || uri || ascii) {
                    setSingleLine(true)
                    if (uri) type = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
                    imeOptions = (if (search) EditorInfo.IME_ACTION_SEARCH else EditorInfo.IME_ACTION_DONE) or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_FLAG_NO_EXTRACT_UI
                    setOnEditorActionListener { _, id, _ ->
                        if (id == EditorInfo.IME_ACTION_SEARCH) { submit(); true } else false
                    }
                } else {
                    type = type or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
                    setMaxLines(maxLines)
                    imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_FLAG_NO_EXTRACT_UI
                }
                inputType = type
                addTextChangedListener(object : TextWatcher {
                    override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
                    override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
                    override fun afterTextChanged(s: Editable?) {
                        val t = s?.toString() ?: ""
                        if (t.length > maxChars) {
                            s?.delete(maxChars, t.length)
                        } else {
                            change(t)
                        }
                    }
                })
                if (autoFocus) post {
                    requestFocus()
                    (ctx.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager).showSoftInput(this, 0)
                }
            }
        },
        update = { v ->
            if (v.text.toString() != value) {
                v.setText(value)
                v.setSelection(value.length)
            }
            v.isEnabled = enabled
            v.hint = hint
        },
    )
}
