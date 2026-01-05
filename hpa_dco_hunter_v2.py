import os
import sys
import ctypes
import platform
import argparse
import json
import hashlib
import time
from datetime import datetime


# ATA CONSTANTS
ATA_IDENTIFY_DEVICE = 0xEC
ATA_READ_NATIVE_MAX_ADDRESS = 0xF8
ATA_READ_NATIVE_MAX_ADDRESS_EXT = 0x27
ATA_DEVICE_CONFIGURATION_IDENTIFY = 0xB1
ATA_DCO_IDENTIFY_SUBCOMMAND = 0xC2

SECTOR_SIZE = 512


# WINDOWS CONSTANTS
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
OPEN_EXISTING = 3
IOCTL_ATA_PASS_THROUGH_DIRECT = 0x0004D030  



# ATA STRUCTURES (Windows)

class ATA_PASS_THROUGH_DIRECT(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("Length", ctypes.c_ushort),
        ("AtaFlags", ctypes.c_ushort),
        ("PathId", ctypes.c_ubyte),
        ("TargetId", ctypes.c_ubyte),
        ("Lun", ctypes.c_ubyte),
        ("ReservedAsUbyte", ctypes.c_ubyte),
        ("DataTransferLength", ctypes.c_ulong),
        ("TimeOutValue", ctypes.c_ulong),
        ("ReservedAsUlong", ctypes.c_ulong),
        ("DataBuffer", ctypes.c_void_p),
        ("PreviousTaskFile", ctypes.c_ubyte * 8),
        ("CurrentTaskFile", ctypes.c_ubyte * 8),
    ]



# ATA HELPERS
def swap_words(b: bytes) -> str:
    """ATA strings are word-swapped."""
    try:
        swapped = b''.join(b[i:i + 2][::-1] for i in range(0, len(b), 2))
        return swapped.decode("ascii", errors="ignore").strip()
    except Exception:
        return ""


def u16(data, word_offset):
    return int.from_bytes(data[word_offset * 2: word_offset * 2 + 2], "little")


def u32(data, word_offset):
    return int.from_bytes(data[word_offset * 2: word_offset * 2 + 4], "little")


def u64(data, word_offset):
    return int.from_bytes(data[word_offset * 2: word_offset * 2 + 8], "little")



# MAIN CLASS
class HPADCOHunterV2:
    def __init__(self, device, case_id):
        self.device = device
        self.case_id = case_id
        self.os_type = platform.system()
        self.handle = None
        self.report = {
            "case_id": case_id,
            "timestamp": datetime.now().isoformat(),
            "device": device,
            "platform": f"{self.os_type} {platform.release()}",
            "findings": {}
        }

    def banner(self):
        print("""
    ################################################################
    #                                                              #
    #   _    _ _____          _____   _____ ____                   #
    #  | |  | |  __ \   /\   |  __ \ / ____/ __ \                  #
    #  | |__| | |__) | /  \  | |  | | |   | |  | |                 #
    #  |  __  |  ___/ / /\ \ | |  | | |   | |  | |                 #
    #  | |  | | |    / ____ \| |__| | |___| |__| |                 #
    #  |_|  |_|_|   /_/    \_\_____/ \_____\____/                  #
    #                                                              #
    #  HPA & DCO Hunter | Artifact Recovery Tool v2.0              #
    #                                                              #
    ################################################################
        """)

    def open_device(self):
        if "nvme" in self.device.lower():
            raise RuntimeError("NVMe devices are NOT supported. Use an ATA/SATA interface.")

        if self.os_type == "Windows":
            # Ensure path is correct for PhysicalDrive
            path = self.device
            if not path.startswith("\\\\.\\"):
                if path.lower().startswith("physicaldrive"):
                    path = "\\\\.\\" + path
                else:
                    # Try to map drive letter to physical drive if needed,
                    # but usually user provides PhysicalDriveX
                    pass

            self.handle = ctypes.windll.kernel32.CreateFileW(
                path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            if self.handle in (None, -1, 0xFFFFFFFFFFFFFFFF):
                err = ctypes.windll.kernel32.GetLastError()
                if err == 5:
                    raise PermissionError("Access Denied. Please run as Administrator.")
                elif err == 2:
                    raise FileNotFoundError(f"Device {path} not found.")
                else:
                    raise RuntimeError(f"Failed to open device. WinError: {err}")
        else:
            try:
                self.handle = os.open(self.device, os.O_RDWR)
            except PermissionError:
                raise PermissionError("Failed to open device. Ensure you have root/sudo privileges.")

    def close_device(self):
        if self.handle:
            if self.os_type == "Windows":
                ctypes.windll.kernel32.CloseHandle(self.handle)
            else:
                os.close(self.handle)

    def send_ata(self, command, features=0, lba=0, count=0, data_in=True):
        """
        Sends an ATA command using PASS_THROUGH_DIRECT for better compatibility.
        """
        data_buffer = ctypes.create_string_buffer(512) if data_in else None

        if self.os_type == "Windows":
            apt = ATA_PASS_THROUGH_DIRECT()
            apt.Length = ctypes.sizeof(apt)
            # ATA_FLAGS_DATA_IN (0x02) or ATA_FLAGS_DRDY_REQUIRED (0x01)
            apt.AtaFlags = 0x02 if data_in else 0x01
            apt.DataTransferLength = 512 if data_in else 0
            apt.TimeOutValue = 10
            if data_in:
                apt.DataBuffer = ctypes.cast(data_buffer, ctypes.c_void_p)

            # Task File: [0]Features, [1]Count, [2]LBA Low, [3]LBA Mid, [4]LBA High, [5]Device, [6]Command
            apt.CurrentTaskFile[0] = features
            apt.CurrentTaskFile[1] = count
            apt.CurrentTaskFile[2] = lba & 0xFF
            apt.CurrentTaskFile[3] = (lba >> 8) & 0xFF
            apt.CurrentTaskFile[4] = (lba >> 16) & 0xFF
            apt.CurrentTaskFile[5] = 0x40 | ((lba >> 24) & 0x0F)  # LBA mode
            apt.CurrentTaskFile[6] = command

            returned = ctypes.c_ulong()
            res = ctypes.windll.kernel32.DeviceIoControl(
                self.handle,
                IOCTL_ATA_PASS_THROUGH_DIRECT,
                ctypes.byref(apt),
                ctypes.sizeof(apt),
                ctypes.byref(apt),
                ctypes.sizeof(apt),
                ctypes.byref(returned),
                None
            )

            if not res:
                return None, None

            return (data_buffer.raw if data_in else b""), bytes(apt.CurrentTaskFile)

        else:
            import fcntl
            # Linux HDIO_DRIVE_CMD
            cmd_buf = bytearray([command, count, features, 0])
            if data_in:
                cmd_buf += bytearray(512)

            try:
                fcntl.ioctl(self.handle, 0x0303, cmd_buf)
                return (bytes(cmd_buf[4:]) if data_in else b""), bytes(cmd_buf[:4])
            except Exception:
                return None, None

    def identify(self):
        data, _ = self.send_ata(ATA_IDENTIFY_DEVICE)
        if not data or len(data) < 512:
            # Fallback: Some controllers might require specific LBA/Count for Identify
            data, _ = self.send_ata(ATA_IDENTIFY_DEVICE, count=1)
            if not data or len(data) < 512:
                raise RuntimeError(
                    "IDENTIFY DEVICE failed. Device might not be ATA compatible or is behind a restrictive controller.")

        lba48_supported = bool(u16(data, 83) & (1 << 10))
        if lba48_supported:
            reported_max = u64(data, 100)
        else:
            reported_max = u32(data, 60)

        info = {
            "model": swap_words(data[54:94]),
            "serial": swap_words(data[20:40]),
            "firmware": swap_words(data[46:54]),
            "lba48_supported": lba48_supported,
            "reported_max_lba": reported_max
        }

        self.report["device_info"] = info
        return info

    def detect_hpa(self, info):
        is_lba48 = info["lba48_supported"]
        cmd = ATA_READ_NATIVE_MAX_ADDRESS_EXT if is_lba48 else ATA_READ_NATIVE_MAX_ADDRESS

        data, tf_out = self.send_ata(cmd, data_in=False)

        if tf_out:
            # tf_out: [0]Error, [1]Count, [2]LBA Low, [3]LBA Mid, [4]LBA High, [5]Device, [6]Status
            native_lba = tf_out[2] | (tf_out[3] << 8) | (tf_out[4] << 16) | ((tf_out[5] & 0x0F) << 24)

            # Note: For LBA48, the registers need to be read twice or via a different IOCTL to get all 48 bits.
            # This version focuses on the standard detection.
            present = native_lba > info["reported_max_lba"]

            return {
                "present": present,
                "reported_max_lba": info["reported_max_lba"],
                "native_max_lba": native_lba if present else info["reported_max_lba"],
                "method": "READ_NATIVE_MAX"
            }

        return {"present": False, "error": "Command failed"}

    def detect_dco(self):
        data, _ = self.send_ata(ATA_DEVICE_CONFIGURATION_IDENTIFY, features=ATA_DCO_IDENTIFY_SUBCOMMAND)
        if data and any(data[:8]):
            return True
        return False

    def read_sector(self, lba):
        try:
            offset = lba * SECTOR_SIZE
            if self.os_type == "Windows":
                li = ctypes.c_longlong(offset)
                ctypes.windll.kernel32.SetFilePointerEx(self.handle, li, None, 0)
                buf = ctypes.create_string_buffer(SECTOR_SIZE)
                read = ctypes.c_ulong()
                ctypes.windll.kernel32.ReadFile(self.handle, buf, SECTOR_SIZE, ctypes.byref(read), None)
                return buf.raw
            else:
                os.lseek(self.handle, offset, os.SEEK_SET)
                return os.read(self.handle, SECTOR_SIZE)
        except Exception:
            return None

    def run(self):
        self.banner()
        print(f"[*] Analyzing device: {self.device}")
        try:
            info = self.identify()
        except Exception as e:
            print(f"[!] Error: {e}")
            return

        print(f"[+] Model: {info['model']}")
        print(f"[+] Serial: {info['serial']}")
        print(f"[+] Reported Max LBA: {info['reported_max_lba']}")

        hpa = self.detect_hpa(info)
        dco_present = self.detect_dco()

        self.report["findings"]["hpa"] = hpa
        self.report["findings"]["dco_present"] = dco_present

        if hpa["present"]:
            print(f"[!] HPA DETECTED! Native Max LBA: {hpa['native_max_lba']}")
            hidden_lba = info["reported_max_lba"] + 1
            data = self.read_sector(hidden_lba)
            if data:
                sha = hashlib.sha256(data).hexdigest()
                self.report["findings"]["hidden_sector_sample_sha256"] = sha
                print(f"[+] Sampled hidden sector {hidden_lba} hash: {sha}")
        else:
            print("[*] No HPA detected via standard ATA commands.")

        if dco_present:
            print("[!] DCO configuration found (Device Configuration Overlay).")
        else:
            print("[*] No DCO detected.")

    def save_report(self):
        filename = f"hpa_dco_report_{self.case_id}_{int(time.time())}.json"
        with open(filename, "w") as f:
            json.dump(self.report, f, indent=4)
        print(f"[+] Forensic report saved to: {filename}")


def main():
    parser = argparse.ArgumentParser(description="HPA/DCO Hunter v2.0 - Forensic Disk Analysis Tool")
    parser.add_argument("device", help="Device path (e.g., PhysicalDrive0 or /dev/sdb)")
    parser.add_argument("--case", default="CASE_001", help="Case identifier")
    args = parser.parse_args()

    hunter = HPADCOHunterV2(args.device, args.case)
    try:
        hunter.open_device()
        hunter.run()
        hunter.save_report()
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        hunter.close_device()


if __name__ == "__main__":
    main()
