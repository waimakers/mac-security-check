#!/bin/sh
# Checks this Mac for indicators of the pine63 / base64-pipe-to-shell macOS stealer.
# Plain POSIX sh: run with `sh mac-stealer-check.sh` from any shell.
# Prints a clear verdict. Exit code: 0 = no indicators found, 1 = indicators found.

found=0
RED=$(printf '\033[1;31m'); GREEN=$(printf '\033[1;32m'); BOLD=$(printf '\033[1m'); RESET=$(printf '\033[0m')

pass() { printf '  %s[OK]%s    %s\n' "$GREEN" "$RESET" "$1"; }
fail() { printf '  %s[FOUND]%s %s\n' "$RED" "$RESET" "$1"; found=1; }
indent() { sed 's/^/            /'; }

printf '%sChecking for stealer indicators...%s\n\n' "$BOLD" "$RESET"

# 1. Shell history: the install command (pine63 domain or base64 -d piped into a shell)
pattern='pine63|base64 (-d|--decode).*[|][[:space:]]*(/bin/)?(z|ba)?sh'
hits=""
count=0
for f in "$HOME/.zsh_history" "$HOME/.bash_history" "$HOME"/.zsh_sessions/*; do
  [ -f "$f" ] || continue
  count=$((count + 1))
  # skip lines that are someone searching for these patterns (grep), not running them
  h=$(grep -naE "$pattern" "$f" 2>/dev/null | grep -v 'grep' | sed "s|^|$f:|")
  [ -n "$h" ] && hits="$hits$h
"
done
if [ -n "$hits" ]; then
  fail "Suspicious command in shell history:"
  printf '%s' "$hits" | cut -c1-160 | indent
else
  pass "Shell history: no pine63 or base64-to-shell command ($count files searched)"
fi

# 2. Fake Apple launch items: Apple's own live in /System/Library, never in these folders
launch_hits=$(find /Library/LaunchDaemons /Library/LaunchAgents "$HOME/Library/LaunchAgents" \
  -maxdepth 1 -iname 'com.apple*' 2>/dev/null)
if [ -n "$launch_hits" ]; then
  fail "Launch item posing as Apple (persistence):"
  printf '%s\n' "$launch_hits" | indent
else
  pass "Launch agents/daemons: no fake com.apple.* items"
fi

# 3. Hidden payload folders posing as Apple
hidden_hits=$(find "$HOME/Library/Application Support" -maxdepth 1 -name '.com.apple*' 2>/dev/null)
if [ -n "$hidden_hits" ]; then
  fail "Hidden folder posing as Apple (payload storage):"
  printf '%s\n' "$hidden_hits" | indent
else
  pass "Application Support: no hidden .com.apple* folders"
fi

line='=============================================='
echo ""
if [ "$found" -eq 1 ]; then
  printf '%s%s\n' "$RED" "$line"
  echo "  RESULT: INDICATORS FOUND - treat this Mac as"
  echo "  compromised. Cut ALL internet now: Wi-Fi off,"
  echo "  no phone hotspot, unplug any network cable."
  echo "  Keep it switched on. Screenshot this and"
  echo "  send it privately to Maarten."
  printf '%s%s\n' "$line" "$RESET"
  exit 1
else
  printf '%s%s\n' "$GREEN" "$line"
  echo "  RESULT: NOT FOUND - no indicators of this"
  echo "  stealer on this Mac."
  printf '%s%s\n' "$line" "$RESET"
  exit 0
fi
