# HPA & DCO Hunter v2.0 | Artifact Recovery Tool

## 🛡️ Overview
**HPA & DCO Hunter v2.0** is a professional-grade Digital Forensics (DF) utility designed to identify and analyze hidden disk areas: **Host Protected Area (HPA)** and **Device Configuration Overlay (DCO)**. 

This tool is engineered for 100% safety and reliability, allowing forensic examiners to bypass Operating System abstractions and communicate directly with disk hardware to reveal hidden data that standard tools cannot see.

---

## 🚀 Key Features
*   **100% Non-Destructive**: Strictly read-only operations. No data is deleted, formatted, or permanently modified.
*   **Multi-Protocol Engine**: Native support for **ATA**, **NVMe**, and **SCSI/USB (SAT)** devices.
*   **Volatile HPA Unlocking**: Temporarily exposes hidden areas for imaging without altering the permanent state of the evidence.
*   **Forensic Reporting**: Generates timestamped JSON audit reports with SHA-256 hashes for Chain of Custody.
*   **Cross-Platform Native APIs**: Uses `ctypes` for Windows `DeviceIoControl` and `fcntl` for Linux `ioctl`.

---

## 🛠️ Installation & Requirements
### Prerequisites
*   **Python 3.8+**
*   **Administrative/Root Privileges**: Required for raw hardware communication.

### Setup
No external libraries are required. The tool runs using only Python's standard library.
1.  Download `hpa_dco_hunter_v2.py`.
2.  Open your terminal or command prompt with elevated privileges.

---

## 📖 Usage Examples

### 🐧 Linux (Root)
Analyze a SATA drive and generate a forensic report:
```bash
sudo python3 hpa_dco_hunter_v2.py /dev/sda --case CASE_001
```

Detect and **volatily unlock** the HPA for imaging:
```bash
sudo python3 hpa_dco_hunter_v2.py /dev/sdb --case CASE_002 --unlock
```

### 🪟 Windows (Administrator)
Analyze a physical drive (e.g., Drive 0):
```powershell
python hpa_dco_hunter_v2.py PhysicalDrive0 --case CASE_WIN_001
```

Analyze an NVMe drive and attempt unlock:
```powershell
python hpa_dco_hunter_v2.py PhysicalDrive1 --case CASE_NVME_001 --unlock
```

---

## 📊 Forensic Report Structure
The tool generates a `forensic_report_[CaseID]_[Timestamp].json` file containing:
*   **Device Metadata**: Model, Serial Number, and Firmware version.
*   **DCO Analysis**: Detection status of Device Configuration Overlays.
*   **HPA Analysis**: Reported vs. Native Max LBA coordinates.
*   **Data Integrity**: SHA-256 hash of the first sector of the hidden area.



---

## ⚖️ Disclaimer
This tool is intended for academic research and professional forensic use. Always use a hardware write-blocker when performing actual forensic acquisitions to ensure 100% data integrity for legal admissibility.
