package com.netpath.lab.log

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList

object SessionLog {
    private val lines = CopyOnWriteArrayList<String>()
    private val _text = MutableStateFlow("")
    val text: StateFlow<String> = _text.asStateFlow()

    private val _status = MutableStateFlow(Status.IDLE)
    val status: StateFlow<Status> = _status.asStateFlow()

    private val _hint = MutableStateFlow("")
    val hint: StateFlow<String> = _hint.asStateFlow()

    enum class Status { IDLE, CONNECTING, CONNECTED, FAILED }

    fun clear() {
        lines.clear()
        publish()
        _status.value = Status.IDLE
        _hint.value = ""
    }

    fun append(message: String) {
        val ts = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())
        lines.add("[$ts] $message")
        if (lines.size > 800) {
            lines.subList(0, lines.size - 800).clear()
        }
        publish()
    }

    fun setStatus(status: Status, hint: String = "") {
        _status.value = status
        if (hint.isNotBlank()) _hint.value = hint
        append("STATUS=$status ${hint.takeIf { it.isNotBlank() } ?: ""}".trim())
    }

    fun export(): String = lines.joinToString("\n")

    private fun publish() {
        _text.value = lines.joinToString("\n")
    }
}
