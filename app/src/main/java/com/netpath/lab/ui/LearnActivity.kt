package com.netpath.lab.ui

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
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

WIRE TECHNIQUES IN THIS LAB
• CUSTOM SETUP hold stack — Direct Connection → Custom SNI (SSL/TLS) → Realm Host v2 → Preserve SNI → TCP Payload → Port 443/80/8080 fallback → nearby server hint → TCP first → www. toggle → keep VPN alive.
• DIRECT — raw SSH. Detect via banner/fingerprint on pack bearer.
• HTTP_INJECT — crafted HTTP before SSH. Validate Host/CONNECT; do not forward off-list IPs.
• TLS_SNI_CLIENTHELLO_ONLY — DPI often only sees ClientHello SNI; SSH follows on same TCP. Classic mismatch: SNI=pack name, IP=VPS.
• TLS_SNI_FULL — complete TLS (stunnel labs). Still enforce destination allowlists.
• Preserve SNI — do not rewrite SNI to SSH hostname.
• Realm Host v2 — alternate realm/dial semantics; must not bypass IP policy.
• TCP Payload — cosmetic prepend bytes; must not bypass IP policy.
• Port fallback — consumer apps retry 443→80→8080; your pack policy must cover all.
• www. toggle — exact hostname match games; allowlists still win on dest IP.
• Keep-alive — battery unrestricted + sticky VPN; look for long-lived multiplex flows.

PASS / FAIL FOR PACK APN
PASS: session fails, stalls, or is fully charged when dial IP ∉ allowlist.
FAIL (finding): unmetered success to your lab VPS while SNI looks like a pack host.

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
3. On pack SIM: run scenario SNI_MISMATCH with Custom SNI set to a pack-like name and Host=VPS IP.
4. Correlate Session log timestamps with UPF/PCRF/DPI logs.
5. File findings; fix allowlist gaps; re-test.

RULES OF ENGAGEMENT
• Only networks you own or have written authorization to test.
• No bundled free/public tunnel servers.
• Do not use this tool to steal service or attack third parties.

See also: docs/SOC_PLAYBOOK.md and docs/LAB_SERVER.md in the project.
""".trimIndent()
    }
}
