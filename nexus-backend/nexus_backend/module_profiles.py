"""Risk profiles for each probe module.

The probe hardware does the *detection* (a badge was clonable, a payload
ran); this backend does the *scoring* — the same division of labor as
AD Risk Auditor, where the LDAP collector gathers facts and the detectors
score them.

Where a module's finding doesn't map cleanly to a MITRE ATT&CK Enterprise
technique, `mitre_attack` is left as `None` rather than forced into the
nearest-sounding ID — ATT&CK Enterprise is built around IT intrusion
techniques, and RF/physical findings (a garage remote being replayable,
for instance) often genuinely fall outside it. Forcing a bad mapping would
be less honest than saying there isn't one.
"""

from __future__ import annotations

from dataclasses import dataclass

from .risk import Impact, Likelihood


@dataclass(frozen=True)
class ModuleRiskProfile:
    module: str
    title_template: str  # {n} substituted with a short detail if provided
    likelihood: Likelihood
    impact: Impact
    mitre_attack: str | None
    control_reference: str
    recommendation: str


# Audit/offensive modules — each one, when it reports a finding, means a
# real weakness was proven to exist (not just suspected).
MODULE_PROFILES: dict[str, ModuleRiskProfile] = {
    # Note: this project's firmware does not implement HID injection (BadUSB) —
    # see the firmware README for why — so there is deliberately no risk
    # profile for it here.
    "rfid_nfc_clone": ModuleRiskProfile(
        module="rfid_nfc_clone",
        title_template="Access badge cloned without cryptographic protection",
        likelihood=Likelihood.MEDIUM,
        impact=Impact.HIGH,
        mitre_attack="T1078 — Valid Accounts",  # closest fit: a cloned badge functions as an illegitimate valid credential
        control_reference="NIST 800-53 PE-3 (Physical Access Control) / IA-5 (Authenticator Management)",
        recommendation=(
            "Migrate from unencrypted 125kHz or default-keyed Mifare Classic badges to a "
            "cryptographically protected credential (e.g. DESFire EV2/EV3, or a mobile "
            "credential with per-session keys)."
        ),
    ),
    "subghz_replay": ModuleRiskProfile(
        module="subghz_replay",
        title_template="Sub-GHz remote signal captured and successfully replayed",
        likelihood=Likelihood.MEDIUM,
        impact=Impact.MEDIUM,
        mitre_attack=None,  # no honest Enterprise ATT&CK fit for fixed-code RF replay
        control_reference="NIST 800-53 PE-3 (Physical Access Control)",
        recommendation=(
            "Replace fixed-code RF remotes (garage doors, gates, barriers) with rolling-code "
            "or cryptographically authenticated equivalents."
        ),
    ),
    "ir_replay": ModuleRiskProfile(
        module="ir_replay",
        title_template="Infrared remote signal captured and replayed",
        likelihood=Likelihood.LOW,
        impact=Impact.LOW,
        mitre_attack=None,
        control_reference="NIST 800-53 PE-3 (Physical Access Control)",
        recommendation="Generally low-risk (IR requires line of sight and short range); note for completeness only.",
    ),
    "wifi_handshake_capture": ModuleRiskProfile(
        module="wifi_handshake_capture",
        title_template="WPA handshake captured; passphrase crackable offline",
        likelihood=Likelihood.MEDIUM,
        impact=Impact.HIGH,
        mitre_attack="T1110 — Brute Force",
        control_reference="NIST 800-63B (Memorized Secret Verifiers) / CIS Control 5.2",
        recommendation="Use a long, random WPA2/WPA3 passphrase (20+ characters) or enterprise (802.1X) authentication instead of a shared PSK.",
    ),
    "wifi_evil_twin": ModuleRiskProfile(
        module="wifi_evil_twin",
        title_template="Client device connected to an unauthorized rogue AP impersonating the trusted SSID",
        likelihood=Likelihood.MEDIUM,
        impact=Impact.HIGH,
        mitre_attack="T1557 — Adversary-in-the-Middle",
        control_reference="NIST 800-53 SC-8 (Transmission Confidentiality) / CIS Control 12",
        recommendation=(
            "Deploy 802.1X (WPA2/WPA3-Enterprise) so clients authenticate the network, not "
            "just the SSID name, and train users to check for certificate warnings."
        ),
    ),
    "zigbee_discovery": ModuleRiskProfile(
        module="zigbee_discovery",
        title_template="Unmanaged Zigbee/IoT device(s) discovered",
        likelihood=Likelihood.LOW,
        impact=Impact.MEDIUM,
        mitre_attack="T1046 — Network Service Discovery",  # approximate fit — IoT-specific recon isn't well covered in Enterprise ATT&CK
        control_reference="NIST 800-53 CM-8 (System Component Inventory)",
        recommendation="Maintain an inventory of IoT/smart-building devices and verify each is authorized and on an appropriately segmented network.",
    ),
    "gpio_debug_interface": ModuleRiskProfile(
        module="gpio_debug_interface",
        title_template="Exposed hardware debug interface (UART/JTAG/SPI) found on a device",
        likelihood=Likelihood.LOW,
        impact=Impact.HIGH,
        mitre_attack=None,  # hardware debug-interface exposure isn't represented in Enterprise ATT&CK
        control_reference="NIST 800-53 PE-3 (Physical Access Control) / SA-11 (Developer Testing)",
        recommendation="Disable or physically remove debug headers on production hardware, or gate them behind authentication before shipping.",
    ),
}


def get_profile(module: str) -> ModuleRiskProfile | None:
    return MODULE_PROFILES.get(module)
