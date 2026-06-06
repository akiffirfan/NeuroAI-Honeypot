"""
Patch fs.pickle — fix /etc/motd to point at the honeyfs Ubuntu MOTD file.

Sets A_REALFILE = '/cowrie/honeyfs/etc/motd' so file_contents() reads our
702-byte Ubuntu banner directly from the honeyfs volume. Also sets A_CONTENTS
to bytes as a fallback for any code path that skips A_REALFILE.

Pre-requisite: /cowrie/honeyfs/etc/motd must already exist (it does — 702 bytes
of Ubuntu 22.04 content written in a prior session).

Usage (from VPS):
  docker cp deploy/module-2-cowrie/fix_motd_pickle.py cowrie:/cowrie/var/log/cowrie/fix_motd.py
  docker exec cowrie python3 /cowrie/var/log/cowrie/fix_motd.py
  docker cp cowrie:/cowrie/var/log/cowrie/fs.pickle /tmp/fs.pickle
  sudo mv /tmp/fs.pickle /opt/honeypot/config/cowrie/fs.pickle
  sudo chown root:root /opt/honeypot/config/cowrie/fs.pickle
  docker exec cowrie python3 -c "import os; os.remove('/cowrie/var/log/cowrie/fix_motd.py')"
  docker exec cowrie python3 -c "import os; os.remove('/cowrie/var/log/cowrie/fs.pickle')"
  cd /opt/honeypot/deploy/module-2-cowrie/ && docker compose restart cowrie
"""

import pickle
import time

PICKLE_IN  = '/cowrie/cowrie-git/src/cowrie/data/fs.pickle'
PICKLE_OUT = '/cowrie/var/log/cowrie/fs.pickle'

# Honeyfs path that already has 702 bytes of Ubuntu content.
MOTD_REALFILE = '/cowrie/honeyfs/etc/motd'

A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_DIR  = 1
T_FILE = 2

# Fallback bytes content (used if A_REALFILE path check is skipped by this Cowrie version).
MOTD = (
    b"Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-140-generic x86_64)\n"
    b"\n"
    b" * Documentation:  https://help.ubuntu.com\n"
    b" * Management:     https://landscape.canonical.com\n"
    b" * Support:        https://ubuntu.com/advantage\n"
    b"\n"
    b"System performance metrics collection disabled by policy (ref: IT#6142).\n"
    b"Contact #ai-infra on Slack for cluster diagnostics access.\n"
    b"\n"
    b"Authorized access only. All sessions are monitored and recorded.\n"
    b"Support: ops@neuro.ai\n"
    b"\n"
)

with open(PICKLE_IN, 'rb') as f:
    fs = pickle.load(f)

# The pickle root IS the '/' directory entry (a 10-element list), not a list of entries.
# Root children are at fs[A_CONTENTS] = fs[7]. Names are strings, not bytes.
root_children = fs[A_CONTENTS]

def find_entry(entries, name, entry_type):
    for entry in entries:
        if isinstance(entry, list) and entry[A_NAME] == name and entry[A_TYPE] == entry_type:
            return entry
    return None

etc_entry = find_entry(root_children, 'etc', T_DIR)
if not etc_entry:
    print('ERROR: /etc directory not found in pickle root')
else:
    motd_entry = find_entry(etc_entry[A_CONTENTS], 'motd', T_FILE)
    if motd_entry:
        old_realfile = motd_entry[A_REALFILE]
        old_contents_type = type(motd_entry[A_CONTENTS]).__name__
        motd_entry[A_REALFILE] = MOTD_REALFILE   # primary: read from honeyfs file
        motd_entry[A_CONTENTS] = MOTD            # fallback: inline bytes
        motd_entry[A_SIZE]     = len(MOTD)
        print(f'Updated /etc/motd:')
        print(f'  A_REALFILE: {repr(old_realfile)} -> {repr(MOTD_REALFILE)}')
        print(f'  A_CONTENTS: {old_contents_type} -> bytes ({len(MOTD)} bytes)')
    else:
        new_motd = ['motd', T_FILE, 0, 0, len(MOTD), 0o100644, time.time(), MOTD, '', MOTD_REALFILE]
        etc_entry[A_CONTENTS].append(new_motd)
        print(f'Created new /etc/motd ({len(MOTD)} bytes, A_REALFILE={MOTD_REALFILE})')

with open(PICKLE_OUT, 'wb') as f:
    pickle.dump(fs, f)
print(f'Saved to {PICKLE_OUT}')
