package com.netpath.lab.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.netpath.lab.R
import com.netpath.lab.config.TransportProtocol
import com.netpath.lab.config.TunnelProfile
import com.netpath.lab.log.SessionLog
import com.netpath.lab.ssh.SshTunnelSession
import com.netpath.lab.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean

class TunnelVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunFd: ParcelFileDescriptor? = null
    private var sshSession: SshTunnelSession? = null
    private var forwarder: SocksTunForwarder? = null
    private var job: Job? = null
    private val active = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val profile = if (Build.VERSION.SDK_INT >= 33) {
                    intent.getSerializableExtra(EXTRA_PROFILE, TunnelProfile::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getSerializableExtra(EXTRA_PROFILE) as? TunnelProfile
                }
                if (profile == null) {
                    SessionLog.setStatus(SessionLog.Status.FAILED, "Missing tunnel profile")
                    stopSelf()
                    return START_NOT_STICKY
                }
                startTunnel(profile)
            }
        }
        return START_STICKY
    }

    private fun startTunnel(profile: TunnelProfile) {
        if (!active.compareAndSet(false, true)) return
        startForeground(NOTIF_ID, buildNotification(profile.keepVpnAlive))
        SessionLog.setStatus(SessionLog.Status.CONNECTING, "Custom Setup: establishing front + SSH…")

        job = scope.launch {
            try {
                logHoldStack(profile)
                val session = connectWithPortFallback(profile)
                sshSession = session

                val builder = Builder()
                    .setSession("NetPath Lab")
                    .addAddress("10.8.0.2", 32)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("1.1.1.1")
                    .setMtu(1500)
                    .setBlocking(true)

                try {
                    builder.addDisallowedApplication(packageName)
                } catch (_: Exception) {
                }

                tunFd = builder.establish()
                    ?: error("VPN establish failed — grant VPN permission and retry")

                val socksPort = session.localSocksPort
                SessionLog.append("TUN up; forwarding via SOCKS 127.0.0.1:$socksPort")
                if (profile.keepVpnAlive) {
                    SessionLog.append("Keep-alive: foreground VPN sticky; avoid spam reconnects")
                }

                forwarder = SocksTunForwarder(
                    tunIn = FileInputStream(tunFd!!.fileDescriptor),
                    tunOut = FileOutputStream(tunFd!!.fileDescriptor),
                    socksHost = "127.0.0.1",
                    socksPort = socksPort,
                    protect = { s -> protect(s) }
                )
                SessionLog.setStatus(
                    SessionLog.Status.CONNECTED,
                    "If this succeeded on a zero-rate/pack APN while dest IP is your VPS (off allowlist), that is a control gap. See Learn."
                )
                forwarder!!.run()
            } catch (e: Exception) {
                SessionLog.setStatus(SessionLog.Status.FAILED, e.message ?: e.toString())
                stopTunnelInternal()
            }
        }
    }

    private fun logHoldStack(profile: TunnelProfile) {
        SessionLog.append(
            "Hold stack: customSetup=${profile.customSetup} path=${profile.pathType} " +
                "front=${profile.frontMode} realmV2=${profile.useRealmHostV2} " +
                "preserveSni=${profile.preserveSni} tcpPayload=${profile.useTcpPayload} " +
                "port=${profile.serverPort} fallback=${profile.portFallback} " +
                "proto=${profile.transportProtocol} wwwToggle=${profile.wwwSniToggle} " +
                "nearby=${profile.preferNearbyServer} keepAlive=${profile.keepVpnAlive}"
        )
        if (profile.transportProtocol == TransportProtocol.UDP) {
            SessionLog.append(
                "Protocol=UDP selected for drill note — SSH front still uses TCP " +
                    "(UDP is faster but flakier for holding; SOC should watch both)."
            )
        }
        if (profile.preferNearbyServer) {
            SessionLog.append(
                "Nearby/stable server preferred — lower RTT usually means fewer idle drops. " +
                    "Confirm lab VPS region is close to the test SIM."
            )
        }
        SessionLog.append("Effective SNI=${TunnelProfile.resolveSni(profile)}")
    }

    private fun connectWithPortFallback(base: TunnelProfile): SshTunnelSession {
        val ports = if (base.customSetup && base.portFallback) {
            val ordered = LinkedHashSet<Int>()
            ordered.add(base.serverPort)
            TunnelProfile.HOLD_PORTS.forEach { ordered.add(it) }
            ordered.toList()
        } else {
            listOf(base.serverPort)
        }

        var lastError: Exception? = null
        for (port in ports) {
            val attempt = base.copy(serverPort = port)
            SessionLog.append("Trying SSH front on port $port …")
            try {
                val session = SshTunnelSession(attempt) { socket -> protect(socket) }
                session.start()
                if (port != base.serverPort) {
                    SessionLog.append("Port fallback succeeded on $port (started with ${base.serverPort})")
                }
                return session
            } catch (e: Exception) {
                lastError = e
                SessionLog.append("Port $port failed: ${e.message}")
                if (!base.portFallback || ports.size == 1) break
            }
        }
        throw lastError ?: IllegalStateException("All hold ports failed")
    }

    private fun stopTunnel() {
        stopTunnelInternal()
        if (SessionLog.status.value == SessionLog.Status.CONNECTED ||
            SessionLog.status.value == SessionLog.Status.CONNECTING
        ) {
            SessionLog.setStatus(SessionLog.Status.IDLE, "Tunnel stopped")
        }
    }

    private fun stopTunnelInternal() {
        active.set(false)
        try {
            forwarder?.close()
        } catch (_: Exception) {
        }
        forwarder = null
        try {
            sshSession?.close()
        } catch (_: Exception) {
        }
        sshSession = null
        try {
            tunFd?.close()
        } catch (_: Exception) {
        }
        tunFd = null
        job?.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnelInternal()
        scope.cancel()
        super.onDestroy()
    }

    private fun buildNotification(keepAlive: Boolean): Notification {
        val channelId = "netpath_vpn"
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(
                    channelId,
                    getString(R.string.channel_vpn),
                    NotificationManager.IMPORTANCE_LOW
                )
            )
        }
        val pi = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val text = if (keepAlive) {
            getString(R.string.vpn_notification_keepalive)
        } else {
            getString(R.string.vpn_notification_text)
        }
        return NotificationCompat.Builder(this, channelId)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_START = "com.netpath.lab.START"
        const val ACTION_STOP = "com.netpath.lab.STOP"
        const val EXTRA_PROFILE = "profile"
        private const val NOTIF_ID = 42

        fun start(context: Context, profile: TunnelProfile) {
            val i = Intent(context, TunnelVpnService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_PROFILE, profile)
            }
            context.startForegroundService(i)
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, TunnelVpnService::class.java).apply { action = ACTION_STOP }
            )
        }
    }
}
