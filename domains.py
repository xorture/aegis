# ==============================================================================
# PROJECT: AEGIS (Advanced Engine for Global Interception & Security)
# FILE:    domains.py
# PURPOSE: Threat Intelligence Database.
#          Contains known malicious domain suffixes used for pattern matching.
# ==============================================================================

# DATA STRUCTURE:
# KEY   = Threat Category (String) -> displayed in logs.
# VALUE = List of Domain Suffixes (List[String]) -> used for filtering.

BLACKLIST_DB = {
    
    # --- TIER 1: MALWARE & C2 (High Severity) ---
    # Infrastructure used by botnets, ransomware, and remote access trojans (RATs).
    "MALWARE_C2": [
        ".ddns.net",        # Dynamic DNS often used by attackers to hide IP addresses.
        ".no-ip.com",       # Dynamic DNS service frequently abused by malware.
        ".duckdns.org",     # Dynamic DNS service.
        ".onion",           # Tor Hidden Services (Dark Web) gateways.
        ".bazar",           # TLD associated with BazarLoader ransomware.
        ".emotet",          # Infrastructure linked to Emotet banking trojan.
        "ngrok.io",         # Tunneling service used to bypass firewalls.
        "pastebin.com"      # Often used to host malicious payloads (raw code).
    ],

    # --- TIER 2: SPYWARE & TELEMETRY (Medium Severity) ---
    # Domains that collect user data, usage statistics, and system diagnostics.
    "SPYWARE_TELEMETRY": [
        # Microsoft Windows Telemetry
        "vortex.data.microsoft.com",
        "telemetry.microsoft.com",
        "settings-win.data.microsoft.com",
        "watson.telemetry.microsoft.com",

        # NVIDIA GPU Telemetry
        "gfe.nvidia.com",
        "telemetry.gfe.nvidia.com",

        # Mobile/App Analytics
        "mobile.pipe.aria.microsoft.com", # Office/Skype telemetry.
        "stats.unity3d.com",              # Unity Engine analytics (in games).
        "tracking.miui.com",              # Xiaomi device tracking.
        "graph.facebook.com"              # Facebook API data collection.
    ],

    # --- TIER 3: ADWARE & TRACKERS (Low Severity) ---
    # Advertising networks and behavioral tracking scripts.
    "AD_TRACKER": [
        ".doubleclick.net",         # Google's primary ad serving domain.
        ".googlesyndication.com",   # Google AdSense.
        ".googleadservices.com",    # Google Ads conversion tracking.
        ".adnxs.com",               # AppNexus (Real-time bidding ads).
        ".criteo.com",              # Retargeting ads (follows you across sites).
        ".taboola.com",             # Content recommendation ads (chumbox).
        ".outbrain.com",            # Similar to Taboola.
        ".scorecardresearch.com",   # Market research and audience measurement.
        ".appsflyer.com",           # Mobile attribution and analytics.
        ".adjust.com"               # Mobile measurement partner.
    ],
    
    # --- TIER 4: CRYPTOJACKING (Resource Theft) ---
    # Scripts that hijack CPU power to mine cryptocurrency in the browser.
    "CRYPTO_MINER": [
        "coin-hive.com",
        "coinhive.com",
        "jsecoin.com",
        "minero.cc",
        "deepminer.org"
    ]
}