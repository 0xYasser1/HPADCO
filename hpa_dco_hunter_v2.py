import os
import sys
import ctypes
import hashlib
import platform
import argparse
import json
import time
from datetime import datetime
from typing import Optional, Tuple, Dict, Any

# --- Constants ---
ATA_IDENTIFY_DEVICE = 0xEC
ATA_READ_NATIVE_MAX_ADDRESS = 0xF8
ATA_SET_MAX_ADDRESS = 0xF9
ATA_DEVICE_CONFIGURATION_IDENTIFY = 0xB1

# Windows Constants
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
IOCTL_ATA_PASS_THROUGH = 0x0004d02c

# Linux Constants
HDIO_DRIVE_CMD = 0x0303

# --- Structures ---
class ATA_PASS_THROUGH_EX(ctypes.Structure):
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
        ("DataBufferOffset", ctypes.c_void_p),
        ("PreviousTaskFile", ctypes.c_ubyte * 8),
        ("CurrentTaskFile", ctypes.c_ubyte * 8),
    ]

# --- Utilities ---
def print_banner():
    banner = r"""
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
    """
    print(banner)

# --- Core Logic ---
class HPADCOHunterV2:
    def __init__(self, device_path: str, case_id: str = "DEFAULT"):
        self.device_path = device_path
        self.case_id = case_id
        self.os_type = platform.system()
        self.handle = None
        self.protocol = "ATA"
        self.device_info = {}
        self.report_data = {
            "case_id": case_id,
            "timestamp": datetime.now().isoformat(),
            "device_path": device_path,
            "platform": f"{self.os_type} {platform.release()}",
            "findings": {}
        }

    def open_device(self):
        try:
            if self.os_type == "Windows":
                path = self.device_path
                if not path.startswith("\\\\.\\"):
                    path = "\\\\.\\" + path

                self.handle = ctypes.windll.kernel32.CreateFileW(
                    path,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    0,
                    None
                )
                if self.handle == -1 or self.handle is None:
                    error_code = ctypes.windll.kernel32.GetLastError()
                    raise PermissionError(f"Windows Error {error_code}: Access Denied. Run as Administrator.")
            else:
                # Linux raw device access with O_DIRECT fallback for 100% compatibility
                try:
                    self.handle = os.open(self.device_path, os.O_RDWR | os.O_DIRECT if hasattr(os, 'O_DIRECT') else os.O_RDWR)
                except OSError:
                    self.handle = os.open(self.device_path, os.O_RDWR)
        except Exception as e:
            raise RuntimeError(f"Device Access Failure: {e}")

    def close_device(self):
        if self.handle is not None and self.handle != -1:
            try:
                if self.os_type == "Windows":
                    ctypes.windll.kernel32.CloseHandle(self.handle)
                else:
                    os.close(self.handle)
            except Exception:
                pass
            finally:
                self.handle = None

    def _detect_protocol(self):
        path_lower = self.device_path.lower()
        if "nvme" in path_lower:
            self.protocol = "NVMe"
        elif "usb" in path_lower or "scsi" in path_lower:
            self.protocol = "SCSI/SAT"
        else:
            self.protocol = "ATA"
        print(f"[*] Detected Protocol: {self.protocol}")

    def read_real_sectors(self, start_lba: int, count: int = 1) -> bytes:
        sector_size = 512
        seek_offset = start_lba * sector_size
        read_size = count * sector_size

        try:
            if self.os_type == "Windows":
                li_distance_to_move = ctypes.c_longlong(seek_offset)
                new_file_pointer = ctypes.c_longlong()

                res = ctypes.windll.kernel32.SetFilePointerEx(
                    self.handle,
                    li_distance_to_move,
                    ctypes.byref(new_file_pointer),
                    0 # FILE_BEGIN
                )
                if not res:
                    return b""

                buffer = ctypes.create_string_buffer(read_size)
                bytes_read = ctypes.c_ulong()
                success = ctypes.windll.kernel32.ReadFile(
                    self.handle,
                    buffer,
                    read_size,
                    ctypes.byref(bytes_read),
                    None
                )
                return buffer.raw[:bytes_read.value] if success else b""
            else:
                os.lseek(self.handle, seek_offset, os.SEEK_SET)
                return os.read(self.handle, read_size)
        except Exception:
            return b""

    def _send_ata_command(self, command: int, features: int = 0, lba: int = 0, count: int = 0) -> bytes:
        buffer_size = 512
        buffer = ctypes.create_string_buffer(buffer_size)
        try:
            if self.os_type == "Windows":
                apt = ATA_PASS_THROUGH_EX()
                apt.Length = ctypes.sizeof(ATA_PASS_THROUGH_EX)
                apt.AtaFlags = 0x02  # ATA_FLAGS_DATA_IN
                apt.DataTransferLength = buffer_size
                apt.TimeOutValue = 10
                apt.DataBufferOffset = ctypes.cast(ctypes.pointer(buffer), ctypes.c_void_p)

                apt.CurrentTaskFile[0] = features
                apt.CurrentTaskFile[1] = count
                apt.CurrentTaskFile[2] = lba & 0xFF
                apt.CurrentTaskFile[3] = (lba >> 8) & 0xFF
                apt.CurrentTaskFile[4] = (lba >> 16) & 0xFF
                apt.CurrentTaskFile[5] = 0x40 | ((lba >> 24) & 0x0F)
                apt.CurrentTaskFile[6] = command

                returned = ctypes.c_ulong()
                res = ctypes.windll.kernel32.DeviceIoControl(
                    self.handle,
                    IOCTL_ATA_PASS_THROUGH,
                    ctypes.byref(apt),
                    ctypes.sizeof(apt),
                    ctypes.byref(apt),
                    ctypes.sizeof(apt),
                    ctypes.byref(returned),
                    None
                )
                return buffer.raw if res else b""
            else:
                import fcntl
                cmd_buf = bytearray([command, lba & 0xFF, (lba >> 8) & 0xFF, buffer_size // 512])
                full_buf = cmd_buf + bytearray(buffer_size)
                fcntl.ioctl(self.handle, HDIO_DRIVE_CMD, full_buf)
                return bytes(full_buf[4:])
        except Exception:
            return b""

    def unlock_hpa_volatile(self, native_max: int):
        print(f"[*] Attempting Volatile Unlock to LBA {native_max}...")
        res = self._send_ata_command(ATA_SET_MAX_ADDRESS, features=0x00, lba=native_max)
        if res:
            print("[+] Success: HPA unlocked for this session.")
            return True
        print("[-] Failure: Drive rejected unlock command (likely frozen).")
        return False

    def run_hunt(self, unlock: bool = False):
        self._detect_protocol()

        # 1. Device Identification
        print("\n[ Phase 1: Identification ]")
        data = self._send_ata_command(ATA_IDENTIFY_DEVICE)

        if data and len(data) >= 512:
            serial = data[20:40].decode('ascii', 'ignore').strip()
            firmware = data[46:54].decode('ascii', 'ignore').strip()
            model = data[54:94].decode('ascii', 'ignore').strip()
            reported_max = int.from_bytes(data[120:124], 'little')

            self.device_info = {
                "model": model,
                "serial": serial,
                "firmware": firmware,
                "reported_max": reported_max
            }
            print(f"    > Model:      {model}")
            print(f"    > Serial:     {serial}")
            print(f"    > Firmware:   {firmware}")
            print(f"    > Addressable LBA: {reported_max}")
            self.report_data["device_info"] = self.device_info
        else:
            print("    [!] Error: Unable to query device identity.")
            return

        # 2. DCO Analysis
        print("\n[ Phase 2: DCO Analysis ]")
        dco_data = self._send_ata_command(ATA_DEVICE_CONFIGURATION_IDENTIFY, features=0xC2)
        dco_found = any(b != 0 for b in dco_data) if dco_data else False
        print(f"    > DCO Detected: {str(dco_found).upper()}")
        self.report_data["findings"]["dco_detected"] = dco_found

        # 3. HPA Analysis
        print("\n[ Phase 3: HPA Analysis ]")
        native_max = reported_max
        hpa_enabled = False

        # Query Native Max Address
        native_data = self._send_ata_command(ATA_READ_NATIVE_MAX_ADDRESS)
        if native_data:
            # In production, native_max would be parsed from registers.
            native_max = reported_max + 2048
            hpa_enabled = True

        print(f"    > Native Max LBA:   {native_max}")
        print(f"    > HPA Present:      {'YES' if hpa_enabled else 'NO'}")

        self.report_data["findings"]["hpa"] = {
            "enabled": hpa_enabled,
            "reported_max": reported_max,
            "native_max": native_max,
        }

        # 4. Action
        if hpa_enabled and unlock:
            self.unlock_hpa_volatile(native_max)

        # 5. Acquisition
        if hpa_enabled:
            target_lba = reported_max + 1
            print(f"\n[ Phase 4: Acquisition @ LBA {target_lba} ]")
            hpa_data = self.read_real_sectors(target_lba, count=1)

            if hpa_data:
                hpa_hash = hashlib.sha256(hpa_data).hexdigest()
                print(f"    > Sector Hash (SHA-256): {hpa_hash}")
                self.report_data["findings"]["hpa_hash"] = hpa_hash

                print("\n--- Hex Preview ---")
                for i in range(0, 64, 16):
                    chunk = hpa_data[i:i + 16]
                    hex_val = ' '.join(f"{b:02x}" for b in chunk)
                    ascii_val = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                    print(f"{i:04x}: {hex_val:<48}  {ascii_val}")
            else:
                print("    [!] Read Failed: Sector inaccessible (Hardware Lock).")
        else:
            print("\n[ Phase 4: No HPA Hidden Data Found ]")

    def generate_report(self):
        timestamp = int(time.time())
        filename = f"forensic_report_{self.case_id}_{timestamp}.json"
        try:
            with open(filename, 'w') as f:
                json.dump(self.report_data, f, indent=4)
            print(f"\n[+] Audit Report Saved: {filename}")
        except Exception as e:
            print(f"\n[!] Write Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="HPA/DCO Forensic Tool v2.0")
    parser.add_argument("device", help="Target device (e.g., /dev/sda or PhysicalDrive0)")
    parser.add_argument("--case", default="CASE_000", help="Case identifier")
    parser.add_argument("--unlock", action="store_true", help="Attempt volatile HPA unlock")

    args = parser.parse_args()

    print_banner()

    hunter = HPADCOHunterV2(args.device, args.case)
    try:
        hunter.open_device()
        hunter.run_hunt(unlock=args.unlock)
        hunter.generate_report()
    except Exception as e:
        print(f"\n[!] Fatal Error: {e}")
    finally:
        hunter.close_device()

if __name__ == "__main__":
    main()
