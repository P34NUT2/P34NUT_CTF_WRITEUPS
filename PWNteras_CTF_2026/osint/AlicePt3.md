# PWNteras CTF 2026 First Edition

# AlicePt3

## OSINT / Networking

**Tags:** `OSINT` `Cellular Networks` `WiFi Geolocation` `BSSID` `MAC Lookup`

---

## Description

> "Hey, don't get mad, but I asked another hacker to help speed up this investigation. He gave me this text I can't understand at all. He says the café where he saw my boyfriend with another woman is in there.
> The problem is, when I asked him how to decode the text, he wanted to charge me 0.0042 BTC. I don't even know what BTC is."

```
http://188.137.168.108:50000?log=%7B%09%0A%09%22data%22:%20%5B%0A%09%09%7B%0A%09%09%09%22MccMnc%22:%20%2233450%22,%0A%09%09%09%22band%22:%20%2266%22,%0A%09%09%09%22TAC%22:%20%229283%22,%0A%09%09%09%22ECI%22:%20%2223981087%22,%0A%09%09%09%22PCI%22:%20%22147%22,%0A%09%09%09%22eNB%22%20:%20%2293676%22,%0A%09%09%09%22LCID%22:%20%2231%22,%0A%09%09%09%22NID%22:%20%2249/0%22%0A%09%09%7D,%0A%09%09%7B%0A%09%09%09%22MccMnc%22:%20%2233450%22,%0A%09%09%09%22band%22:%20%227%22,%0A%09%09%09%22TAC%22:%20%220%22,%0A%09%09%09%22ECI%22:%20%220%22,%0A%09%09%09%22PCI%22:%20%22193%22,%0A%09%09%09%22eNB%22%20:%20%220%22,%0A%09%09%09%22LCID%22:%20%220%22,%0A%09%09%09%22NID%22:%20%2264/1%22%0A%09%09%7D,%0A%09%09%7B%0A%09%09%09%22Mac%22:%20%2202:00:00:00:00:00%22,%0A%09%09%09%22BSSID%22:%20%2200:4e:35:05:69:d3%22,%0A%09%09%09%22signal%22:%20%22-65%20dBm%22,%0A%09%09%09%22DNS%22:%20%221.1.1.1%22,%0A%09%09%09%22security%22:%20null%0A%09%09%7D%0A%09%5D%0A%7D
```

The flag format is:
`pwnteras_love{cafe_name.AAA}`

`AAA` is the modem/antenna vendor name, abbreviated for the NYSE. Example: `pwnteras_love{cafeteria_de_mario.HPE}`. The café name must be all lowercase with spaces replaced by underscores.

---

## Files

> This challenge did not provide any files — only the description above.

---

## Analysis

We start with a long URL that is clearly URL-encoded. Decoding it (via CyberChef or any URL decoder) reveals the following JSON payload:

```json
{
  "data": [
    {
      "MccMnc": "33450",
      "band": "66",
      "TAC": "9283",
      "ECI": "23981087",
      "PCI": "147",
      "eNB": "93676",
      "LCID": "31",
      "NID": "49/0"
    },
    {
      "MccMnc": "33450",
      "band": "7",
      "TAC": "0",
      "ECI": "0",
      "PCI": "193",
      "eNB": "0",
      "LCID": "0",
      "NID": "64/1"
    },
    {
      "Mac": "02:00:00:00:00:00",
      "BSSID": "00:4e:35:05:69:d3",
      "signal": "-65 dBm",
      "DNS": "1.1.1.1",
      "security": null
    }
  ]
}
```

The server IP (`188.137.168.108`) resolves to Sweden, but the `MccMnc` value `33450` maps clearly to **Mexico** (MCC `334`, MNC `50` = AT&T / IUSACell), so Sweden is a red herring — this is data collected from a device in Mexico.

```
334   50   mx   Mexico   52   AT&T / IUSACell
Source: https://mcc-mnc.com/
```

### Key Field Definitions

**Cellular Tower Data (LTE/4G):**

| Field | Meaning |
|-------|---------|
| `MccMnc` | Mobile Country Code + Network Code — identifies country and carrier |
| `band` | LTE frequency band (66 = AWS-3, 7 = IMT-E — both used by AT&T Mexico) |
| `TAC` | Tracking Area Code — groups towers for mobility management |
| `ECI` | E-UTRAN Cell Identity — globally unique cell ID (composed of eNB + LCID) |
| `PCI` | Physical Cell ID (0–503) — local identifier, not globally unique |
| `eNB` | eNodeB ID — the base station. **Most important field for geolocation.** Derived as ECI ÷ 256 (23981087 ÷ 256 = 93676) |
| `LCID` | Local Cell ID — sector within the tower (0–255). ECI = (eNB × 256) + LCID |
| `NID` | Non-standard field, specific to the logging app |

**WiFi Data:**

| Field | Meaning |
|-------|---------|
| `Mac` | Scanning device MAC — `02:00:00:00:00:00` is a randomized/private MAC (Android/iOS privacy feature) |
| `BSSID` | Access point MAC address — **key field for WiFi geolocation** |
| `signal` | Signal strength in dBm — `-65 dBm` = good signal (~10–20m range), device was **inside** the venue |
| `DNS` | `1.1.1.1` = Cloudflare public DNS — no geolocation value |
| `security` | `null` = **open WiFi network** — confirms a public venue (café, restaurant, etc.) |

---

## Theory

To solve this challenge you need to understand:

- **OSINT** — Open Source Intelligence techniques and tooling
- **Cellular Network Identifiers** — MCC, MNC, TAC, ECI, eNB and how they relate
- **WiFi Geolocation** — using BSSID databases to locate access points
- **MAC OUI Lookup** — identifying hardware vendors from MAC addresses
- **Patience** ;)

---

## Solution

### Step 1: Identify the Cell Tower

Using the [OSINT Framework](https://osintframework.com/), we find two relevant tools: a cell tower database and a WiFi geolocation database.

We start with **OpenCellID** (https://opencellid.org), entering the MCC, MNC, TAC, and eNB values:

<img width="2110" height="758" alt="Osint_framework_tools" src="https://github.com/user-attachments/assets/3083b1d3-9adf-40b8-931f-b6483a9c42e6" />

```
MCC: 334
MNC: 50
LAC / TAC: 9283
Radio Type: LTE

Latitude:  19.36339
Longitude: -99.186718
Range: 1000 m

Measurements: 2
Last Updated: 2025-12-12T04:56:44.000Z
```

This gives us a geographic area in Mexico City to narrow our search.

<img width="1215" height="531" alt="Antena" src="https://github.com/user-attachments/assets/00724d30-a856-4958-bb95-1f78aff10a9e" />

### Step 2: Geolocate the WiFi Access Point

Next, we use **WiGLE** (https://wigle.net/) — a crowdsourced database of WiFi networks. We search using the coordinates from Step 1 and the BSSID `00:4e:35:05:69:d3`.

WiGLE returns the precise location of that access point:

<img width="2133" height="860" alt="BSSID" src="https://github.com/user-attachments/assets/aa2f80eb-797d-4fb5-98ff-490ffd45bc20" />

### Step 3: Identify the Venue

With the exact coordinates, we open **Google Maps** and examine the location. The result is a café at that address:

<img width="2677" height="1510" alt="Cafe" src="https://github.com/user-attachments/assets/e20f581c-9d00-41dc-b825-b5af699b92df" />

The café name gives us the first part of the flag: `cafe_del_sur`.

### Step 4: Identify the Vendor

The flag format requires the **NYSE-abbreviated vendor name** of the access point manufacturer. We look up the BSSID OUI using a MAC lookup tool:

```
https://maclookup.app/search/result?mac=00:4e:35:05:69:d3
```

The first three octets (`00:4e:35`) identify the manufacturer as **Hewlett Packard Enterprise**, abbreviated as **HPE** — matching the format shown in the example.

### Step 5: Construct the Flag

Combining both pieces:

- Venue: `cafe_del_sur`
- Vendor abbreviation: `HPE`

**TARGET FOUND!** 🎯

---

## Flag

```
pwnteras_love{cafe_del_sur.HPE}
```

---

## How to Avoid

This challenge demonstrates how **passive RF data logging** (cellular and WiFi identifiers captured by a device) can be weaponized for geolocation tracking without the subject's knowledge or consent. Here is how individuals and organizations can protect themselves:

### 1. **MAC Address Randomization**

Modern operating systems (Android 10+, iOS 14+) randomize MAC addresses per network by default. However, some apps and devices bypass this. Users should:

- Verify MAC randomization is **enabled per-network** in WiFi settings
- Avoid connecting to open networks, which log your BSSID interactions
- Be aware that the scanning device's MAC (`02:00:00:00:00:00`) was already randomized in this challenge — but the **access point's BSSID is always fixed** and traceable

### 2. **Avoid Open / Public WiFi Networks**

The `"security": null` field confirmed the network was open. Open networks:

- Are indexed by wardriving databases like WiGLE, Mylnikov, and Google's geolocation API
- Allow passive geolocation by anyone who logs your BSSID
- Should be avoided for sensitive activities — use a VPN if necessary

### 3. **Cellular Network Exposure**

LTE cell tower IDs (`eNB`, `TAC`, `ECI`) are broadcast openly by towers and can be logged by any device with a compatible radio. To reduce exposure:

- Disable cellular data when not in use
- Be aware that SIM-based apps may log and transmit tower data
- Enterprise users should audit mobile apps for unauthorized RF logging

### 4. **Audit Apps with Location/Network Permissions**

The data in this challenge was captured by an app that logged both cellular and WiFi metadata. Users and administrators should:

- Regularly audit which apps have access to **location**, **WiFi state**, and **network state** permissions
- Revoke unnecessary permissions on mobile devices
- Use MDM (Mobile Device Management) solutions to enforce permission policies in corporate environments

### Example: Detecting Suspicious RF Logging (Python)

```python
import json

# Flags suspicious network log payloads that expose geolocation-sensitive fields
SENSITIVE_FIELDS = {"ECI", "eNB", "TAC", "BSSID", "MccMnc"}

def audit_log(payload: dict) -> list[str]:
    warnings = []
    for entry in payload.get("data", []):
        found = SENSITIVE_FIELDS.intersection(entry.keys())
        if found:
            warnings.append(f"Sensitive RF fields detected: {found}")
    return warnings

with open("network_log.json") as f:
    data = json.load(f)

issues = audit_log(data)
for issue in issues:
    print(f"[WARNING] {issue}")
```

### 5. **For Venue Operators**

Cafés and public venues whose WiFi BSSIDs are indexed in public databases can be precisely located by anyone. To reduce exposure:

- Change BSSID/MAC periodically if the hardware supports it (some enterprise APs allow this)
- Register with WiGLE's opt-out program: https://wigle.net/optout
- Use guest network isolation to prevent unauthorized data harvesting from clients

### References

- [OWASP Mobile Security Testing Guide — Network Communication](https://owasp.org/www-project-mobile-security-testing-guide/)
- [WiGLE Opt-Out](https://wigle.net/optout)
- [OpenCellID Project](https://opencellid.org)
- [Android MAC Randomization Documentation](https://source.android.com/docs/core/connect/wifi-mac-randomization)
- [Apple Privacy — WiFi MAC Randomization](https://support.apple.com/en-us/102509)

---

> **Author:** Jose Antonio Villafaña Montes de Oca
