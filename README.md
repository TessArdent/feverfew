# Feverfew

Feverfew is a free Windows diagnostics tool. Run it once to get a single report on a PC's hardware, firmware, drivers and recent crashes, with likely problems and suggested fixes at the top. Use it to troubleshoot your own PC, support someone else's, or keep a record of a machine's health.

Named after feverfew, a daisy-like flower long used as a home remedy.

## Using it

1. Download `setup.exe` from the [latest release](https://github.com/TessArdent/feverfew/releases/latest) and run it. No admin rights are needed to install.
2. Open Feverfew and accept the Windows permission prompt, then press **Run diagnostics**. A scan takes under a minute.
3. Press **Show file to send** and send that `.html` file to whoever is helping.

Reports are saved in `Feverfew Reports` on the Desktop.

`setup.exe` isn't code-signed, so Windows SmartScreen may warn about it. Choose **More info**, then **Run anyway**. Each release lists the file's SHA-256 hash so you can check your download.

## What it collects

| Area | Details |
| --- | --- |
| Motherboard and BIOS | Maker, model, revision, BIOS version and date, UEFI or Legacy boot, Secure Boot |
| Boot and Secure Boot | Setup Mode, platform key, allowed and revoked signature counts, trusted certificates, the BIOS's default keys, Windows' Secure Boot certificate update status, firmware boot entries, EFI boot loaders and who signed them, and whether the firmware trusts the Windows boot file |
| TPM and security | TPM version, maker and state, BitLocker on or off, virtualization-based security, antivirus, firewall |
| Processor and memory | CPU model, cores, speeds, each RAM module, rated speed (from the part number when Windows reports only the fallback speed), actual speed, slots used |
| Graphics and devices | GPU and driver details, monitors, sound, USB devices, devices with errors, third-party drivers |
| Storage | Drive type and health, SMART failure prediction, temperature, wear, power-on hours, GPT or MBR for each disk, every partition (including EFI and recovery), unallocated space, fixed and removable volumes, free space |
| Windows | Edition, build, activation, uptime, pending restarts, recent updates, power settings |
| Software | Installed programs, startup programs, stopped services, top memory use |
| Crashes | Blue screen stop codes, repeated stop codes, the time of each unexpected shutdown, drivers logging large numbers of errors, hardware (WHEA) errors, disk errors, program crashes, last 30 days of event log errors |
| Network | Adapters, addresses, DNS, proxy, router, internet and name lookup tests |
| Gaming | Power plan, Game Mode, background recording, GPU scheduling, memory integrity, connection type, latency, jitter and packet loss, TCP and network adapter settings, NVIDIA power, PCIe and Resizable BAR details, AMD driver details, refresh rate |
| Battery | Charge, wear, cycles (laptops) |
| Windows 11 | Readiness for each hardware requirement, except Microsoft's supported CPU list |

The report comes as an `.html` file to read and a `.json` file with the same content for scripts.

## Privacy

- **Nothing is uploaded.** Feverfew has no telemetry. A scan's only network traffic is the connection tests: pings to the router and to `1.1.1.1` (about 20 each, to measure latency), and a name lookup for `www.microsoft.com`. Use `--no-network` to skip it. **Check for updates** contacts GitHub only when you press it, and sends no report data.
- **Identifiers are hidden by default.** Serial numbers, the system UUID, computer and user names, drive labels, MAC addresses, public IP addresses, and email addresses in log messages become `[hidden]`. Tick the checkbox to keep them, for example for a warranty claim.
- **Feverfew never reads** product keys, BitLocker recovery keys, passwords, browser data or personal files.
- **Reports still say a lot about a PC.** The installed programs list, for one, is included even with identifiers hidden. Only send a report to someone you trust, and glance through it first if that matters to you.

## Repair tools

**Repair tools** lists the usual fixes. Each one runs in its own administrator window, only when you press **Run**. Fixes that need a restart or change settings ask first. Every report also lists these commands, so whoever is helping can see the options.

| Fix | Command |
| --- | --- |
| Create a restore point | `Checkpoint-Computer` |
| Check or repair the Windows image | `DISM /Online /Cleanup-Image /CheckHealth`, `/RestoreHealth` |
| Repair system files | `sfc /scannow` |
| Scan or repair the Windows drive | `chkdsk %SystemDrive% /scan`, `/f` |
| Test the memory | `mdsched.exe` |
| Clear the DNS cache | `ipconfig /flushdns` |
| Reset network settings | `netsh winsock reset`, `netsh int ip reset` |
| Reset Windows Update | Stops its services and renames its cache folders |

## Gaming

**Gaming** lists optional changes and shows whether each is worth applying on this PC. Each one runs in its own administrator window, only when you press **Apply**, and most have an **Undo**. The page also suggests settings to check in NVIDIA or AMD's own app, because Feverfew can't safely change those. Feverfew leaves out popular tweaks with no reliable benefit, and doesn't offer to turn off security features such as memory integrity.

| Option | Command |
| --- | --- |
| High performance power plan | `powercfg /setactive SCHEME_MIN` |
| Game Mode, background recording, GPU scheduling | `reg add` on the matching Windows setting |
| Turn off Energy Efficient Ethernet | `Set-NetAdapterAdvancedProperty` on `*EEE` |
| Restore default TCP settings | `netsh int tcp set global autotuninglevel=normal`, `rss=enabled`, `netsh int tcp set heuristics disabled` |
| Restore default multimedia settings | `reg add` on `NetworkThrottlingIndex` and `SystemResponsiveness` |

## Updates

**Check for updates** looks at this repository's latest release. If there's a newer version, Feverfew offers to download `setup.exe`, verifies its SHA-256 against the hash GitHub publishes for that file, and runs it. Publishing a new GitHub release with a `setup.exe` asset and a tag like `v1.3.0` is all it takes to ship an update.

## Command line

```text
Feverfew.exe --cli [--out <folder>] [--include-identifiers] [--no-network]
Feverfew.exe --check-update
```

Run it from an elevated prompt for a full scan. Without administrator rights it still runs, but can't read the TPM, BitLocker, SMART prediction or crash dumps, and the report says so.

## Building

You need the [.NET SDK](https://dotnet.microsoft.com/download) (8 or later) and [Inno Setup 6](https://jrsoftware.org/isinfo.php).

```powershell
.\build.ps1
```

This creates `dist\setup.exe`. The app targets .NET Framework 4.8, which comes with current Windows 10 and 11, so friends don't have to install a runtime.

## License

[MIT](LICENSE)
