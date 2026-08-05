package com.netpath.lab.config

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * Persists the active lab profile in EncryptedSharedPreferences.
 * Export/import uses clear JSON for SOC tickets (operator-controlled).
 */
class ProfileStore(context: Context) {
    private val gson = Gson()
    private val prefs: SharedPreferences = createPrefs(context.applicationContext)

    fun load(): TunnelProfile {
        val json = prefs.getString(KEY_PROFILE, null) ?: return TunnelProfile()
        return runCatching { gson.fromJson(json, TunnelProfile::class.java) }
            .getOrElse { TunnelProfile() }
    }

    fun save(profile: TunnelProfile) {
        prefs.edit { putString(KEY_PROFILE, gson.toJson(profile)) }
    }

    fun exportJson(profile: TunnelProfile): String = gson.toJson(profile)

    /** Redacts secrets for safer ticket sharing while keeping front-door settings. */
    fun exportJsonRedacted(profile: TunnelProfile): String =
        gson.toJson(
            profile.copy(
                password = if (profile.password.isNotEmpty()) "***REDACTED***" else "",
                privateKeyPem = if (profile.privateKeyPem.isNotEmpty()) "***REDACTED***" else ""
            )
        )

    fun importJson(json: String): TunnelProfile {
        val type = object : TypeToken<TunnelProfile>() {}.type
        return gson.fromJson(json, type)
    }

    private fun createPrefs(context: Context): SharedPreferences {
        return try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                context,
                PREFS_ENCRYPTED,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (_: Exception) {
            // Fallback if Keystore unavailable on emulator/device
            context.getSharedPreferences(PREFS_FALLBACK, Context.MODE_PRIVATE)
        }
    }

    companion object {
        private const val PREFS_ENCRYPTED = "netpath_lab_secure_prefs"
        private const val PREFS_FALLBACK = "netpath_lab_prefs"
        private const val KEY_PROFILE = "active_profile"
    }
}
