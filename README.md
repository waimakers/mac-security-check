# Mac security check

Checks a Mac for indicators of a known macOS stealer (pine63 / base64-pipe-to-shell install command, fake Apple launch items, hidden fake Apple folders). Read-only: it changes nothing on your machine.

Run in Terminal:

```
curl -fsSL https://raw.githubusercontent.com/waimakers/mac-security-check/main/mac-stealer-check.sh -o ~/Downloads/mac-stealer-check.sh && sh ~/Downloads/mac-stealer-check.sh
```

Green "NOT FOUND" means no indicators. Red "INDICATORS FOUND" means: cut all internet (Wi-Fi, hotspot, cable), keep the Mac switched on, and send a screenshot privately to Maarten.

## Windows PC

Checks a Windows PC for the same campaign (encoded-PowerShell / download-to-iex install command in history or the Win+R Run box, autostart and scheduled-task persistence calling the attacker infrastructure, and dropped files or hosts entries matching the known IOCs). Read-only, no admin needed.

Run in PowerShell (downloads the script to a file first, then runs it, so you can inspect it before running):

```
powershell -ExecutionPolicy Bypass -Command "iwr https://raw.githubusercontent.com/waimakers/mac-security-check/main/win-stealer-check.ps1 -OutFile $env:TEMP\win-stealer-check.ps1; & $env:TEMP\win-stealer-check.ps1"
```

Same verdict: green "NOT FOUND" means no indicators; red "INDICATORS FOUND" means cut all internet, keep the PC switched on, and send a screenshot privately to Maarten.
