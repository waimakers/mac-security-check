# Mac security check

Checks a Mac for indicators of a known macOS stealer (pine63 / base64-pipe-to-shell install command, fake Apple launch items, hidden fake Apple folders). Read-only: it changes nothing on your machine.

Run in Terminal:

```
curl -fsSL https://raw.githubusercontent.com/waimakers/mac-security-check/main/mac-stealer-check.sh -o ~/Downloads/mac-stealer-check.sh && sh ~/Downloads/mac-stealer-check.sh
```

Green "NOT FOUND" means no indicators. Red "INDICATORS FOUND" means: cut all internet (Wi-Fi, hotspot, cable), keep the Mac switched on, and send a screenshot privately to Maarten.
