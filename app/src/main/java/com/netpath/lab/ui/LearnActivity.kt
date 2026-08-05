package com.netpath.lab.ui

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.netpath.lab.config.TrainingScenarios
import com.netpath.lab.databinding.ActivityLearnBinding

class LearnActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val binding = ActivityLearnBinding.inflate(layoutInflater)
        setContentView(binding.root)
        title = "SOC / Learn"
        binding.learnContent.text = CONTENT
    }

    companion object {
        private val METHOD_CATALOG = TrainingScenarios.all.joinToString("\n\n") { s ->
            buildString {
                appendLine(s.title)
                appendLine(s.description)
                appendLine("Defender: ${s.defenderHint}")
                s.steps.forEachIndexed { i, step -> appendLine("  ${i + 1}. $step") }
            }.trimEnd()
        }

        private val CONTENT = """
NetPath Lab — SOC education (authorized use only)

WHAT THIS APP MODELS
Consumer tunnel apps (e.g. HA Tunnel–class) often:
1) Open TCP to a server (frequently :443)
2) Optionally send HTTP inject text or a TLS ClientHello with a Custom SNI
3) Keep or rewrite that SNI (Preserve SNI / Realm Host style toggles)
4) Run SSH2 on that path and multiplex device traffic (VPN)

Your job as an ISP is not to “block SSH forever on the internet APN”.
It is to stop abuse of PACK / ZERO-RATE bearers when the destination is NOT an allowlisted CDN/service IP.

BILLING / ZERO-RATE SCORING
PASS: session fails, stalls, or is fully charged when dial IP ∉ allowlist.
FAIL (finding): unmetered success to your lab VPS while SNI/Host looks like a pack host.
Always dial an operator-owned VPS — never free public SSH lists.

METHODS CATALOG (in-app spinner)
$METHOD_CATALOG

ADVANCED SOC CHECKLIST (may not be separate app toggles)
• APN / wrong bearer confusion — confirm the phone is on the pack APN under test.
• IPv6 vs IPv4 asymmetry — app drills are IPv4-focused; enforce the same allowlists on IPv6.
• Over-broad CDN ASN allowlists — entire hosting/CDN ASNs create unmetered escape hatches.

DEFENDER CONTROLS (PRIORITY ORDER)
1. Pack/zero-rate = destination IP/prefix allowlists (automated, tight).
2. SNI present + dest IP not in list → deny or rate.
3. Same policy on IPv4 and IPv6 and every APN.
4. Default-deny odd DNS/UDP/ICMP tunnels on pack bearer.
5. Hosting-ASN + long multiplex flow scoring + quotas.
6. Active probe off-CDN destinations claiming pack SNI.
7. Do NOT rely on SNI string filters alone.

HOW TO RUN A TEAM DRILL
1. Deploy OpenSSH on YOUR VPS (see docs/LAB_SERVER.md). Prefer :443.
2. On Wi‑Fi/paid data: confirm Direct SSH works (control).
3. On pack SIM: apply method 1 (SNI mismatch) or 11 (full hold stack).
4. Correlate Session log timestamps with UPF/PCRF/DPI logs.
5. File findings; fix allowlist gaps; re-test.

RULES OF ENGAGEMENT
• Only networks you own or have written authorization to test.
• No bundled free/public tunnel servers.
• Do not use this tool to steal service or attack third parties.

See also: docs/methods.html, docs/SOC_PLAYBOOK.md, docs/LAB_SERVER.md.
""".trimIndent()
    }
}
