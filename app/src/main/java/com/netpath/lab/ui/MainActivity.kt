package com.netpath.lab.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import com.netpath.lab.NetPathApp
import com.netpath.lab.config.FrontMode
import com.netpath.lab.config.PathType
import com.netpath.lab.config.TrainingScenarios
import com.netpath.lab.config.TransportProtocol
import com.netpath.lab.config.TunnelProfile
import com.netpath.lab.databinding.ActivityMainBinding
import com.netpath.lab.log.SessionLog
import com.netpath.lab.vpn.TunnelVpnService
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private val frontModes = FrontMode.entries.toTypedArray()
    private val holdPorts = TunnelProfile.HOLD_PORTS
    private val protocols = TransportProtocol.entries.toTypedArray()

    private val vpnPermission = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startTunnelService()
        } else {
            SessionLog.setStatus(SessionLog.Status.FAILED, "VPN permission denied")
        }
    }

    private val notifPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* continue regardless */ }

    private val importConfig = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri == null) return@registerForActivityResult
        runCatching {
            contentResolver.takePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        }
        runCatching {
            val json = contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
                ?: throw IllegalArgumentException("Empty file")
            val profile = NetPathApp.instance.profileStore.importJson(json)
            if (profile.serverHost.isBlank()) {
                throw IllegalArgumentException("Missing serverHost in config")
            }
            NetPathApp.instance.profileStore.save(profile)
            bindProfile(profile)
            SessionLog.append("Imported profile: ${profile.name}")
            Toast.makeText(this, "Imported: ${profile.name}", Toast.LENGTH_SHORT).show()
        }.onFailure { e ->
            Toast.makeText(this, "Import failed: ${e.message}", Toast.LENGTH_LONG).show()
            SessionLog.append("Import failed: ${e.message}")
        }
    }

    private val exportProfile = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        if (uri == null) return@registerForActivityResult
        val profile = readProfileFromForm()
        runCatching {
            contentResolver.openOutputStream(uri)?.use { out ->
                out.write(NetPathApp.instance.profileStore.exportJson(profile).toByteArray())
            }
            Toast.makeText(this, "Profile exported", Toast.LENGTH_SHORT).show()
            SessionLog.append("Exported profile: ${profile.name}")
        }.onFailure { e ->
            Toast.makeText(this, "Export failed: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        binding.spinnerPath.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            listOf("Direct Connection")
        )
        binding.spinnerFront.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            frontModes.map {
                when (it) {
                    FrontMode.TLS_SNI_CLIENTHELLO_ONLY -> "Custom SNI (SSL/TLS Mode)"
                    FrontMode.TLS_SNI_FULL -> "Custom SNI full TLS"
                    FrontMode.HTTP_INJECT -> "HTTP Inject"
                    FrontMode.DIRECT -> "Direct (no SNI front)"
                    FrontMode.HTTP_WEBSOCKET_TLS -> "WebSocket upgrade + TLS SNI"
                    FrontMode.HTTP2_PREAMBLE_TLS -> "HTTP/2 preface + TLS SNI"
                    FrontMode.TLS_CHROME_JA3_MIMIC -> "Chrome JA3 mimic ClientHello"
                    FrontMode.TROJAN_HTTP_CAMOUFLAGE -> "Trojan HTTP camouflage"
                }
            }
        )
        binding.spinnerPort.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            holdPorts.map { it.toString() }
        )
        binding.spinnerProtocol.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            protocols.map {
                when (it) {
                    TransportProtocol.TCP -> "TCP (best for holding)"
                    TransportProtocol.UDP -> "UDP (faster, flakier)"
                }
            }
        )
        binding.spinnerScenario.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_dropdown_item,
            TrainingScenarios.all.map { it.title }
        )
        binding.spinnerScenario.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                showMethodPreview(position)
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
        showMethodPreview(0)

        bindProfile(NetPathApp.instance.profileStore.load())
        wireCustomSetupListeners()

        binding.btnApplyScenario.setOnClickListener {
            val scenario = TrainingScenarios.all.getOrNull(binding.spinnerScenario.selectedItemPosition)
                ?: return@setOnClickListener
            val applied = scenario.apply(readProfileFromForm())
            bindProfile(applied)
            val stepsText = TrainingScenarios.formatSteps(scenario)
            binding.methodStepsView.text = stepsText
            SessionLog.append("Applied method ${scenario.id}")
            SessionLog.append(scenario.defenderHint)
            scenario.steps.forEachIndexed { i, step ->
                SessionLog.append("  step ${i + 1}: $step")
            }
            Toast.makeText(this, scenario.defenderHint, Toast.LENGTH_LONG).show()
        }

        binding.btnSave.setOnClickListener {
            val p = readProfileFromForm()
            NetPathApp.instance.profileStore.save(p)
            Toast.makeText(this, "Profile saved", Toast.LENGTH_SHORT).show()
        }

        binding.btnLearn.setOnClickListener {
            startActivity(Intent(this, LearnActivity::class.java))
        }

        binding.btnBattery.setOnClickListener { requestBatteryUnrestricted() }

        binding.btnConnect.setOnClickListener {
            SessionLog.clear()
            val prepare = VpnService.prepare(this)
            if (prepare != null) {
                vpnPermission.launch(prepare)
            } else {
                startTunnelService()
            }
        }

        binding.btnDisconnect.setOnClickListener {
            TunnelVpnService.stop(this)
        }

        binding.btnExport.setOnClickListener { exportSessionBundle() }

        binding.btnImportConfig.setOnClickListener {
            importConfig.launch(arrayOf("application/json", "text/plain", "*/*"))
        }

        binding.btnExportProfile.setOnClickListener {
            val profile = readProfileFromForm()
            val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
            val safeName = profile.name
                .lowercase(Locale.US)
                .replace(Regex("[^a-z0-9]+"), "-")
                .trim('-')
                .ifBlank { "lab-profile" }
            exportProfile.launch("$safeName-$stamp.nplab.json")
        }

        lifecycleScope.launch {
            SessionLog.text.collectLatest { binding.logView.text = it }
        }
        lifecycleScope.launch {
            SessionLog.status.collectLatest { status ->
                binding.statusBanner.text = "Status: $status"
            }
        }
        lifecycleScope.launch {
            SessionLog.hint.collectLatest { binding.hintText.text = it }
        }
    }

    private fun showMethodPreview(position: Int) {
        val scenario = TrainingScenarios.all.getOrNull(position) ?: return
        binding.methodStepsView.text = TrainingScenarios.formatSteps(scenario)
    }

    private fun wireCustomSetupListeners() {
        binding.switchCustomSetup.setOnCheckedChangeListener { _, checked ->
            binding.customSetupPanel.visibility = if (checked) View.VISIBLE else View.GONE
            if (checked) {
                // Default Custom Setup to SNI SSL/TLS mode
                val sniIdx = frontModes.indexOf(FrontMode.TLS_SNI_CLIENTHELLO_ONLY)
                if (sniIdx >= 0) binding.spinnerFront.setSelection(sniIdx)
            }
            refreshEffectiveSni()
        }
        binding.switchWww.setOnCheckedChangeListener { _, _ -> refreshEffectiveSni() }
        binding.inputSni.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) = refreshEffectiveSni()
        })
        binding.spinnerPort.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                binding.inputPort.setText(holdPorts[position].toString())
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
    }

    private fun refreshEffectiveSni() {
        val draft = readProfileFromForm()
        binding.effectiveSniLabel.text = "Effective SNI: ${TunnelProfile.resolveSni(draft)}"
    }

    private fun requestBatteryUnrestricted() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            Toast.makeText(this, "Not required on this Android version", Toast.LENGTH_SHORT).show()
            return
        }
        val pm = getSystemService(PowerManager::class.java)
        if (pm.isIgnoringBatteryOptimizations(packageName)) {
            Toast.makeText(this, "Already unrestricted", Toast.LENGTH_SHORT).show()
            SessionLog.append("Battery optimizations already ignored")
            return
        }
        try {
            startActivity(
                Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
            )
            SessionLog.append("Requested battery unrestricted (keep VPN alive)")
        } catch (_: Exception) {
            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
        }
    }

    private fun startTunnelService() {
        val profile = readProfileFromForm()
        if (profile.serverHost.isBlank() || profile.username.isBlank()) {
            Toast.makeText(this, "Server host and username required", Toast.LENGTH_SHORT).show()
            return
        }
        if (profile.password.isBlank() && profile.privateKeyPem.isBlank()) {
            Toast.makeText(this, "Password or private key required", Toast.LENGTH_SHORT).show()
            return
        }
        if (profile.keepVpnAlive && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val pm = getSystemService(PowerManager::class.java)
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                SessionLog.append("Tip: enable battery unrestricted for hold-stack drills")
            }
        }
        NetPathApp.instance.profileStore.save(profile)
        TunnelVpnService.start(this, profile)
    }

    private fun bindProfile(p: TunnelProfile) {
        binding.inputName.setText(p.name)
        binding.inputHost.setText(p.serverHost)
        binding.inputPort.setText(p.serverPort.toString())
        binding.inputUser.setText(p.username)
        binding.inputPassword.setText(p.password)
        binding.inputKey.setText(p.privateKeyPem)
        binding.inputSni.setText(p.customSni)
        binding.inputHttp.setText(p.httpPayload)
        binding.inputTcpHex.setText(p.tcpPayloadHex)
        binding.switchCustomSetup.isChecked = p.customSetup
        binding.customSetupPanel.visibility = if (p.customSetup) View.VISIBLE else View.GONE
        binding.switchPreserve.isChecked = p.preserveSni
        binding.switchRealm.isChecked = p.useRealmHostV2
        binding.switchTcpPayload.isChecked = p.useTcpPayload
        binding.switchPortFallback.isChecked = p.portFallback
        binding.switchNearby.isChecked = p.preferNearbyServer
        binding.switchWww.isChecked = p.wwwSniToggle
        binding.switchKeepAlive.isChecked = p.keepVpnAlive
        val idx = frontModes.indexOf(p.frontMode).coerceAtLeast(0)
        binding.spinnerFront.setSelection(idx)
        val portIdx = holdPorts.indexOf(p.serverPort).let { if (it >= 0) it else 0 }
        binding.spinnerPort.setSelection(portIdx)
        binding.spinnerProtocol.setSelection(protocols.indexOf(p.transportProtocol).coerceAtLeast(0))
        binding.spinnerPath.setSelection(0)
        refreshEffectiveSni()
    }

    private fun readProfileFromForm(): TunnelProfile {
        val existing = NetPathApp.instance.profileStore.load()
        val portFromField = binding.inputPort.text?.toString()?.toIntOrNull()
        val port = portFromField
            ?: holdPorts.getOrElse(binding.spinnerPort.selectedItemPosition) { 443 }
        return existing.copy(
            name = binding.inputName.text?.toString().orEmpty().ifBlank { "Lab profile" },
            serverHost = binding.inputHost.text?.toString()?.trim().orEmpty(),
            serverPort = port,
            username = binding.inputUser.text?.toString()?.trim().orEmpty(),
            password = binding.inputPassword.text?.toString().orEmpty(),
            privateKeyPem = binding.inputKey.text?.toString().orEmpty(),
            frontMode = frontModes.getOrElse(binding.spinnerFront.selectedItemPosition) {
                FrontMode.TLS_SNI_CLIENTHELLO_ONLY
            },
            customSni = binding.inputSni.text?.toString()?.trim().orEmpty(),
            httpPayload = binding.inputHttp.text?.toString().orEmpty(),
            tcpPayloadHex = binding.inputTcpHex.text?.toString()?.trim().orEmpty(),
            preserveSni = binding.switchPreserve.isChecked,
            useRealmHostV2 = binding.switchRealm.isChecked,
            useTcpPayload = binding.switchTcpPayload.isChecked,
            customSetup = binding.switchCustomSetup.isChecked,
            pathType = PathType.DIRECT_CONNECTION,
            transportProtocol = protocols.getOrElse(binding.spinnerProtocol.selectedItemPosition) {
                TransportProtocol.TCP
            },
            wwwSniToggle = binding.switchWww.isChecked,
            portFallback = binding.switchPortFallback.isChecked,
            preferNearbyServer = binding.switchNearby.isChecked,
            keepVpnAlive = binding.switchKeepAlive.isChecked
        )
    }

    private fun exportSessionBundle() {
        val profile = readProfileFromForm()
        val bundle = buildString {
            appendLine("=== NetPath Lab export (authorized SOC use) ===")
            appendLine("Profile (secrets redacted):")
            appendLine(NetPathApp.instance.profileStore.exportJsonRedacted(profile))
            appendLine()
            appendLine("=== Session log ===")
            appendLine(SessionLog.export())
        }
        val file = File(cacheDir, "netpath_lab_export.txt")
        file.writeText(bundle)
        val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", file)
        val share = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "NetPath Lab session + config")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(share, "Export log + config"))
    }
}
