# HPA & DCO Hunter v2.0

## Forensic Disk Artifact Detection Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/Version-2.0-blue.svg)](https://github.com/your-repo/hpa-dco-hunter/releases/tag/v2.0)
[![Status](https://img.shields.io/badge/Status-Read--Only%20Detection-brightgreen.svg)]()

---

## 📖 Project Description

**HPA & DCO Hunter v2.0** is a low-level digital forensics utility designed to detect hidden storage areas on ATA/SATA hard drives created by two primary mechanisms:

1.  **HPA (Host Protected Area)**
2.  **DCO (Device Configuration Overlay)**

These mechanisms can be maliciously abused to hide data from the operating system, standard disk utilities, and even some traditional forensic tools. The tool operates by communicating **directly with the disk firmware** using raw ATA commands, completely bypassing filesystem-level abstractions.

### Intended Use Cases

This project is specifically intended for:

*   Digital forensics investigations
*   Incident response
*   Academic research into disk geometry
*   Anti-forensics detection
*   Cybersecurity learning and experimentation

> ⚠️ **Safety Note:** This tool is **read-only** by design and does **NOT** modify the disk state or geometry in any way.

---

## ✨ Features

The tool focuses on providing accurate, low-level detection of hidden areas.

| Feature | Description |
| :--- | :--- |
| **Raw ATA Commands** | Sends raw ATA commands directly to the disk controller. |
| **Metadata Extraction** | Extracts and reports `IDENTIFY DEVICE` information. |
| **HPA Detection** | Detects HPA presence by comparing the **Reported Max LBA** against the **Native Max LBA**. |
| **DCO Detection** | Detects DCO presence via the `Device Configuration Identify` command. |
| **Hidden Sector Sampling** | Attempts to read a single sector beyond the reported disk size (HPA region) to prove accessibility. |
| **Forensic Reporting** | Generates a structured forensic JSON report with hashes and metadata. |
| **Cross-Platform** | Works on Windows and Linux (ATA/SATA only). |

### 🚫 What the Tool Does NOT Do

This tool focuses on **detection and evidence**, not remediation or recovery.

*   ❌ Does **NOT** remove HPA or DCO.
*   ❌ Does **NOT** write to the disk or change disk geometry.
*   ❌ Does **NOT** support NVMe drives.
*   ❌ Does **NOT** fully dump the contents of hidden areas.
*   ❌ Does **NOT** bypass hardware RAID or USB bridges that block ATA passthrough.
*   ❌ Does **NOT** guarantee detection on all controllers (due to controller-specific behavior).

---

## 🛠️ Supported Platforms & Devices

For best results, connect the target drive directly via SATA.

### Operating System Support

| OS | Status | Required Access | ATA Passthrough Method |
| :--- | :--- | :--- | :--- |
| **Windows** | ✅ Supported | Administrator | ATA Pass Through Direct |
| **Linux** | ✅ Supported | Root (`sudo`) | `HDIO_DRIVE_CMD` ioctl |
| **macOS** | ❌ Not Supported | N/A | N/A |
| **NVMe** | ❌ Not Supported | N/A | N/A |

### Supported Devices

*   ✅ ATA / SATA HDDs
*   ✅ ATA SSDs (limited usefulness)
*   ❌ NVMe drives
*   ❌ USB enclosures that block ATA passthrough
*   ❌ Hardware RAID volumes

---

## 🔬 Technical Deep Dive

### How HPA Detection Works

The presence of a Host Protected Area (HPA) is determined by comparing two key LBA values:

1.  **`IDENTIFY DEVICE` (Reported Max LBA):** The size the operating system and standard tools see.
2.  **`READ NATIVE MAX ADDRESS` (Native Max LBA):** The true, physical size of the disk.

The tool sends the `IDENTIFY DEVICE` command, reads the reported LBA, and then sends the `READ NATIVE MAX ADDRESS` (using 28-bit or 48-bit LBA commands).

> **Detection Logic:** If the **Native Max LBA** is greater than the **Reported Max LBA**, an HPA is present.

### How DCO Detection Works

Device Configuration Overlay (DCO) is detected by:

1.  Sending the `DEVICE CONFIGURATION IDENTIFY` command.
2.  Checking the returned data for active configuration overlays.

> **Detection Logic:** The presence of a non-zero response in the relevant fields indicates DCO usage.

### Hidden Sector Sampling

If an HPA is successfully detected, the tool performs a crucial step to prove the existence of accessible hidden data:

*   It reads **one sector** immediately beyond the reported disk size.
*   It computes a **SHA-256 hash** of this sector.
*   This hash is stored in the forensic report.

This process is intended as **proof of hidden accessible data**, not full data recovery.

---

## 🚀 Usage

The tool requires elevated privileges to access the raw disk device.

### Windows (Administrator Required)

```bash
python hpa_dco_hunter.py PhysicalDrive0 --case CASE_123
```

### Linux (Root Required)

```bash
sudo python3 hpa_dco_hunter.py /dev/sdb --case CASE_123
```

---

## 📊 Output

The tool generates a comprehensive JSON forensic report containing all findings and metadata.

### Report Contents

*   Case ID and Timestamp
*   Platform details
*   Disk model, serial number, and firmware version
*   LBA capabilities
*   HPA detection results (including Native Max LBA)
*   DCO detection status
*   SHA-256 hash of the sampled hidden sector (if accessible)

### Example Output

```json
{
  "case_id": "CASE_123",
  "timestamp": "2026-01-05T18:10:22",
  "device_info": {
    "model": "WDC WD5000AAKX",
    "serial": "WD-WCC2E1234567",
    "lba48_supported": true,
    "reported_max_lba": 976773168
  },
  "findings": {
    "hpa": {
      "present": true,
      "native_max_lba": 976773888
    },
    "dco_present": false,
    "hidden_sector_sample_sha256": "a1c3...e9f2"
  }
}
```

---

## 🛡️ Permissions & Safety

> ⚠️ **Administrator / Root privileges are required** because ATA passthrough bypasses filesystem protections, and the OS blocks raw disk access by default.

The tool is designed to be safe for forensic use when used correctly:

*   It does not write to the disk.
*   It does not change disk geometry.
*   It is strictly a **read-only** utility.

### Limitations & Accuracy

Results should always be treated with forensic caution and verified:

*   Some controllers may fake or block ATA responses.
*   USB-to-SATA bridges often prevent the necessary ATA commands from passing through.
*   DCO detection is presence-based, not a full decoding of the overlay configuration.

> **Verification Requirement:** Results should always be **correlated with other forensic tools** and **verified on another system** if the findings are critical to a case.

---

## ⚖️ Legal & Ethical Notice

This tool is intended **only for authorized forensic analysis**.

**You must have explicit authorization to use this tool on a disk you do not own.**

Unauthorized disk access may violate:

*   Computer misuse laws
*   Privacy regulations
*   Organizational policies

The user of this tool is solely responsible for ensuring compliance with all applicable laws and ethical guidelines.

---

## 👤 Author & Disclaimer

This project was developed as a forensic research and learning project by a Cyber Security student with a focus on low-level disk behavior, anti-forensics techniques, evidence validation, and ATA protocol analysis.

### Disclaimer

This software is provided **“as-is” without warranty**. The author assumes no responsibility for data loss, hardware damage, or legal misuse.
