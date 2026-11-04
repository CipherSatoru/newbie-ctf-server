FILES = {}

FILES["README.md"] = r"""# Newbie Linux CTF (about 1 hour)

You need Linux: Ubuntu, a Linux VM, WSL on Windows, or Termux on Android (Mac also works).
You need internet ONLY for the setup step. The challenges themselves run offline.

1. Unzip this folder and open a terminal inside it.
2. Run:  bash setup.sh
   Type your name (nickname is fine) TWICE, carefully. It then shows your NAME and your PLAYER CODE.
   Write both down. You need BOTH on the website.
3. Read CHALLENGES.md, then open the ctf_workspace folder:  cd ctf_workspace
4. Solve the challenges and submit each flag at: __SERVER__
   (log in with the same name + player code, pick the challenge, paste the flag)
5. New to Linux? Read example/EXAMPLE.md and LINUX_CHEATSHEET.md first.

Rules: solve it yourself. Your files are unique to you, so other people's flags will not work for you.
Re-running setup with the same name gives the same flags (keep the hidden .ctf_code_* file).
"""

FILES["CHALLENGES.md"] = r"""# Challenges (about 1 hour total)
Work inside ctf_workspace/. Each flag looks like flag{abc123def456}.
Submit on the site with your name + player code.

1. Welcome (5 pts) - Open challenge01/welcome.txt. Tools: pwd, ls, cd, cat
2. Hidden (5) - The flag is in a hidden file. Tool: ls -a
3. Lost (10) - One of many folders has flag.txt. Tool: find . -name
4. Needle (10) - Find the line with KEY in a huge log. Tool: grep
5. Locked (10) - You cannot read locked.txt. Why? Tools: ls -l, chmod
6. Odd One Out (15) - One line appears only once. Tools: sort, uniq, pipes |
7. Encoded (15) - Looks like gibberish. Maybe encoded more than once. Tool: base64 -d
8. Mystery (15) - What type of file is mystery? Open it. Tools: file, tar
9. Run It (20) - Make the script runnable, set the env variable, run it. Tools: chmod +x, export, ./
10. Catch the Attacker (25) - In access.log find the IP with the most failed logins (401), then run ./check.sh <ip>. Tools: grep, awk, sort, uniq -c

Stuck? Use man <command> or <command> --help. See LINUX_CHEATSHEET.md.
"""

FILES["LINUX_CHEATSHEET.md"] = r"""# Linux cheat sheet
- pwd where am I | ls, ls -a, ls -l list | cd dir, cd .. move
- cat file read | less file scroll | head/tail file | nano file edit
- mkdir, touch, cp, mv, rm | man cmd manual | cmd --help
- Permissions: ls -l shows rwx. chmod u+r file, chmod +x script
- grep "text" file search | grep -i, grep -r "text" .
- find . -name "name" find files
- Pipes: cmd1 | cmd2 | > write to file | sort, uniq, uniq -c, wc -l
- echo "hi" | base64, base64 -d decode | file x what is it | tar xzf x extract
- Variables: export NAME=value, echo $NAME, env
- Run a script: ./script.sh (needs +x) | sudo run as admin | whoami, id
"""

FILES["example/EXAMPLE.md"] = r"""# Worked example (not scored)
Say a file note.txt contains: The flag is flag{example_this_is_what_it_looks_like}

    ls            # see note.txt
    cat note.txt  # read it, copy the flag{...}

Then submit on the site. Real flags are different for every player.
"""

FILES["setup.sh"] = r"""#!/usr/bin/env bash
SERVER="${CTF_SERVER:-__SERVER__}"
cd "$(dirname "$0")" || exit 1
command -v curl >/dev/null 2>&1 || { echo "curl is required. Install it (e.g. sudo apt install curl) and run again."; exit 1; }
norm(){ printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -s ' ' | sed 's/^ //;s/ $//'; }
echo "=== Newbie Linux CTF setup ==="
echo "You need internet for THIS step only. The challenges themselves are offline."
echo "Your flags are tied to your NAME. Use the same name on the CTF website."
read -rp "Enter your name (nickname is fine): " RAW
NAME=$(norm "$RAW"); [ -z "$NAME" ] && { echo "Name can't be empty."; exit 1; }
echo; echo "Your name will be saved as:  $NAME"
echo "(capitals and extra spaces don't matter, spelling does)"
read -rp "Type it again to confirm: " RAW2
[ "$NAME" = "$(norm "$RAW2")" ] || { echo "Names didn't match. Run bash setup.sh again."; exit 1; }

CF=".ctf_code_$(printf '%s' "$NAME" | sha256sum | cut -c1-8)"; CODE=""
[ -f "$CF" ] && CODE=$(cat "$CF")
echo "Contacting the CTF server (the first call can take up to a minute)..."
RESP=$(curl -s --max-time 120 -X POST --data-urlencode "name=$NAME" --data-urlencode "code=$CODE" "$SERVER/api/setup")
case "$RESP" in
  ERROR=*) echo "${RESP#ERROR=}"; echo "(If this is YOUR name from before, keep the hidden .ctf_code_* file in this folder.)"; exit 1;;
  CODE=*) ;;
  *) echo "Could not reach the server. Check your internet and run again."; exit 1;;
esac
CODE=$(printf '%s\n' "$RESP" | sed -n 's/^CODE=//p'); echo "$CODE" > "$CF"
flag(){ if [ "$1" = decoy ]; then printf '%s\n' "$RESP" | sed -n 's/^DECOY=//p'; else printf '%s\n' "$RESP" | sed -n "s/^F$1=//p"; fi; }
SB=$(flag 1)
seed(){ echo $((16#$(printf '%s' "$SB|seed$1" | sha256sum | cut -c1-6))); }

W=ctf_workspace; rm -rf $W; mkdir -p $W
echo "Welcome, $NAME. The challenge list is in ../CHALLENGES.md" > $W/README.txt

# 1 cat
mkdir $W/challenge01; echo "Welcome to the CTF! Your flag is: $(flag 1)" > $W/challenge01/welcome.txt
echo "expired test flag: $(flag decoy)" > $W/challenge01/old_flag.txt
# 2 hidden
mkdir $W/challenge02; echo "$(flag 2)" > $W/challenge02/.hidden_flag; echo "Nothing to see here." > $W/challenge02/boring.txt
# 3 find
d=$W/challenge03; names=(alpha bravo charlie delta echo); idx=$(( $(seed 3) % 5 ))
for i in 0 1 2 3 4; do mkdir -p $d/${names[$i]}/deep/deeper
 if [ $i = $idx ]; then echo "$(flag 3)" > $d/${names[$i]}/deep/deeper/flag.txt; else echo "Not here." > $d/${names[$i]}/deep/deeper/not_it.txt; fi; done
# 4 grep
mkdir $W/challenge04
awk -v s="$(seed 4)" -v f="$(flag 4)" 'BEGIN{srand(s);split("login logout upload download update error timeout",ev," ");pos=int(rand()*1500)+200;
for(i=1;i<=2000;i++){ if(i==pos) printf "2025-01-01 12:%02d:%02d SECRET_KEY=%s\n",int(i/60)%60,i%60,f; else printf "2025-01-01 12:%02d:%02d INFO user%d %s\n",int(i/60)%60,i%60,int(rand()*50),ev[int(rand()*7)+1]}}' > $W/challenge04/server.log
echo "2025-01-01 12:00:00 DEBUG leftover=$(flag decoy)" >> $W/challenge04/server.log
# 5 permissions
mkdir $W/challenge05; echo "$(flag 5)" > $W/challenge05/locked.txt; chmod 000 $W/challenge05/locked.txt
# 6 sort | uniq
mkdir $W/challenge06
{ for i in $(seq 1 150); do printf 'token-%04d\ntoken-%04d\n' $((i*7)) $((i*7)); done; flag 6; } | sort -R > $W/challenge06/data.txt
# 7 base64 x2
mkdir $W/challenge07; flag 7 | base64 | tr -d '\n' | base64 | tr -d '\n' > $W/challenge07/encoded.txt; echo >> $W/challenge07/encoded.txt
# 8 file type
mkdir $W/challenge08; t=$(mktemp -d); flag 8 > $t/flag.txt; (cd $t && tar czf mystery flag.txt); mv $t/mystery $W/challenge08/mystery; rm -rf $t
# 9 chmod + env var
mkdir $W/challenge09; B9=$(flag 9 | base64 | tr -d '\n')
cat > $W/challenge09/run_me.sh <<EOT
#!/usr/bin/env bash
if [ "\$CTF_MODE" != "on" ]; then
  echo "Access denied. This script wants an environment variable CTF_MODE set to on."; exit 1
fi
echo "Access granted:"; echo "$B9" | base64 -d
EOT
chmod 644 $W/challenge09/run_me.sh
# 10 final: log analysis
mkdir $W/challenge10; ips=(); for i in 1 2 3 4 5 6 7 8; do ips+=("$(( 11 + $(seed 10$i)%200 )).$(( $(seed 11$i)%250 )).$(( $(seed 12$i)%250 )).$(( 1 + $(seed 13$i)%250 ))"); done
ATK=${ips[$(( $(seed 10) % 8 ))]}
awk -v s="$(seed 10)" -v atk="$ATK" -v ips="${ips[*]}" 'BEGIN{srand(s);n=split(ips,a," ");split("/home /login /admin /api /about",p," ");
for(i=1;i<=600;i++){ if(rand()<0.25){ip=atk;st=401;pa="/login"} else {ip=a[int(rand()*n)+1];st=(rand()<0.1)?401:200;pa=p[int(rand()*5)+1]}
printf "%s - [2025-01-01 13:%02d:%02d] \"GET %s\" %d\n",ip,int(i/60)%60,i%60,pa,st}}' > $W/challenge10/access.log
H=$(printf '%s' "$ATK" | sha256sum | cut -d' ' -f1); B10=$(flag 10 | base64 | tr -d '\n')
cat > $W/challenge10/check.sh <<EOT
#!/usr/bin/env bash
if [ -z "\$1" ]; then echo "Usage: ./check.sh <ip-address>"; exit 1; fi
if [ "\$(printf '%s' "\$1" | sha256sum | cut -d' ' -f1)" = "$H" ]; then
  echo "Correct! Attacker caught. Your flag:"; echo "$B10" | base64 -d
else echo "Wrong IP. Look at the failed logins (401) again."; fi
EOT
chmod +x $W/challenge10/check.sh

echo; echo "=============================================="
echo "  Your name:         $NAME"
echo "  Your PLAYER CODE:  $CODE"
echo "  Write both down. You need BOTH on the website."
echo "=============================================="
echo "Next: read CHALLENGES.md, then:  cd $W"
"""
