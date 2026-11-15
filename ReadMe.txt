Build: chmod +x setup.sh ratgen.py && ./setup.sh && python3 ratgen.py

What each piece does:

ratgen.py — the menu-driven builder. Four output paths per OS. Windows builds generate raw shellcode via msfvenom, encrypt with RC4, embed in a custom C loader, compile with mingw, pack with UPX. The x64 loader uses Hell's Gate (fresh ntdll from disk, syscall numbers extracted from the export directory, direct syscall stubs written to executable memory) — this bypasses userland API hooks that EDR/AV place on Nt* functions. AMSI and ETW are patched to ret before execution. x86 loader uses the same AMSI/ETW/RC4 pipeline but resolves Nt* via GetProcAddress (x86 Hell's Gate stubs are messy with stdcall cleanup; the GetProcAddress path still bypasses signature detection because the shellcode is encrypted and AMSI is dead). PowerShell output uses an AMSI bypass + Add-Type P/Invoke for VirtualAlloc/CreateThread.

listeners/simple_listener.py — threaded TCP listener for shell_reverse_tcp payloads. Handles multiple simultaneous sessions with sessions/use <id> REPL.

setup.sh — installs mingw-w64 (both arches), UPX, JDK, Android build-tools, and Metasploit if missing.

Gotchas:

AV bypass is a moving target. The syscall-unhooking loader defeats userland hooks and signature matching for the shellcode itself. But Defender's cloud-delivered protection (MAPS) and behavioral detection can still flag the loader's behavior (RW→RX transition, CreateThread into a fresh allocation, reading ntdll from disk). Test against current Defender definitions and rebuild with different UPX flags or add sleep/jitter if needed. Metasploit's windows/x64/meterpreter/reverse_tcp shellcode is heavily signatured — consider windows/x64/shell_reverse_tcp with a custom stage, or generate with msfvenom --encrypt aes256 and wrap again.

x64 loader expects C:\Windows\System32\ntdll.dll to exist — true on every Windows install, but the loader breaks if run under a filesystem redirection (e.g. SysWOW64 context). That's why x86 and x64 loaders are separate.

DLL loaders execute on DLL_PROCESS_ATTACH in a new thread. For sideloading, name the DLL to match a hijackable import and drop it in the target directory.

Android relies on msfvenom's Meterpreter APK. There is no android/shell/reverse_tcp in msfvenom — Android is Meterpreter-only unless you write a custom Java TCP shell APK.

macOS output is a raw Mach-O from msfvenom, wrapped in an .app bundle. Gatekeeper will quarantine anything unsigned — user must right-click → Open, or xattr -d com.apple.quarantine.

USB autorun: modern Windows blocks autorun.inf execution from removable drives by default (since Vista). It still works for optical media and in some legacy/enterprise configurations. The macOS .command requires the user to double-click and dismiss Gatekeeper.

First run of the Android signer creates build/ratgen.keystore with password ratgen. Change it for production use.