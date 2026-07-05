# GamerIntegrity
Windows PC checker built for gamers, server owners, staff teams, tournament admins, and communities that want a cleaner way to review a setup without forcing players through messy browser-first reports.

It gives you an in-app scan flow, clean result pages, redacted sharing, non-redacted local review, and simple single-EXE releases.

---

## Preview

> Will be updated soon.

```md
![GamerIntegrity Scan Page](assets/preview-scan.png)

![GamerIntegrity Results Page](assets/preview-results.png)

![GamerIntegrity Detections](assets/preview-detections.png)
```

## What GamerIntegrity Does

GamerIntegrity helps check a Windows PC for integrity-related flags, launch traces, suspicious folders, browser/download hits, startup traces, external device history, hardware details, and other signals that may matter during a fair-play review.

It is made to help communities review a PC more clearly, not to instantly label someone as cheating.

---

## Features

* Clean Windows app interface
* In-app scan results
* No forced browser popup after every scan
* Redacted and Non-Redacted result views
* Reports are only created when exported
* Table of Contents for jumping around scan results
* Search inside loaded results
* Pagination for easier reading
* Collapsible detection categories
* Admin restart screen when needed
* Styled in-app modals
* Single-EXE self-contained Windows releases
* Gamer-facing wording and layout

---

## Download

Go to the latest release:

https://github.com/GamerIntegrity/gamerintegrity/releases/latest

Most players should download:

```text
GamerIntegrity-win-x64.exe
```

Other builds:

```text
GamerIntegrity-win-x86.exe
GamerIntegrity-win-arm64.exe
```

Use `x64` for most gaming PCs.

---

## How to Use

1. Download the correct EXE from the releases page.
2. Open GamerIntegrity.
3. Click **Restart as Admin** if the app asks.
4. Click **Run Scan**.
5. Wait for the scan to finish.
6. Choose the result view:

   * **Redacted** — better for sharing
   * **Non-Redacted** — full local PC view
7. Export a report only when you actually need one.

---

## Redacted vs Non-Redacted

### Redacted

Use **Redacted** when the results need to be shared with staff, server owners, tournament admins, or another player.

This view is made for safer sharing. It keeps sensitive local details hidden while still showing the important flags.

### Non-Redacted

Use **Non-Redacted** when the full local detail is needed.

Only use this view when the person looking at the results is trusted.

---

## Result Categories

GamerIntegrity organizes results into simple sections:

* **Overview** — scan result summary
* **Detections** — important flags found during the scan
* **Timeline** — scan and activity timeline
* **Projects** — possible cheat projects, source folders, or build traces
* **Launch** — launch and execution traces
* **Downloads** — browser/download related hits
* **Startup** — running and startup traces
* **Reversal** — installed app hits related to reverse engineering or tooling
* **Browser** — browser keyword hits
* **Files / Folders** — file and folder matches
* **External Devices** — USB and external device history
* **Hardware** — PC hardware info

---

## Fair Play Reminder

GamerIntegrity is a PC checker, not an instant ban button.

Some flags can come from old downloads, dev tools, browser history, test folders, unrelated software, or normal PC use. Always review the full picture before making a decision.

The goal is better information, cleaner reviews, and fairer calls.

---

## Build From Source

Requirements:

* Windows 10 or Windows 11
* Visual Studio 2026 or newer
* .NET Desktop workload installed

Clone the repo:

```bash
git clone https://github.com/GamerIntegrity/gamerintegrity.git
cd gamerintegrity
```

Build:

```bat
build.bat
```

Publish all Windows release builds:

```bat
publish-all-windows.bat
```

Package release files:

```bat
package-release.bat
```

Release output:

```text
release/GamerIntegrity-win-x64.exe
release/GamerIntegrity-win-x86.exe
release/GamerIntegrity-win-arm64.exe
```

---

## Windows Support

GamerIntegrity is a Windows app.

Release builds are self-contained single EXE files, so players should not need to install the .NET Desktop Runtime separately.

Supported release targets:

```text
win-x64
win-x86
win-arm64
```

---

## Support the Project

GamerIntegrity is built for the gaming community.

If this project helps your server, tournament, staff team, or community, you can support DayZero Anticheat here:

https://buymeacoffee.com/dayzeroac

Every bit of support helps keep the project moving.

---

## Links

GitHub:

https://github.com/GamerIntegrity/gamerintegrity

Latest release:

https://github.com/GamerIntegrity/gamerintegrity/releases/latest

Buy Me a Coffee:

https://buymeacoffee.com/dayzeroac

---

## Rights

All rights reserved by DayZero Anticheat.
