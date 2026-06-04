"""
Patches the Cowrie fs.pickle to replace the old AWS canarytoken key+secret
with the new ones. Walks the entire honeyfs tree and replaces byte-level
occurrences in any file's A_CONTENTS.

Run inside the Cowrie container from /cowrie/var/log/cowrie/
"""
import pickle

OLD_KEY    = b'AKIAYZM57LXRGIYTCOUV'
NEW_KEY    = b'AKIAZBUZ6W7DPJO2JWVF'
OLD_SECRET = b'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'
NEW_SECRET = b'KJXtQadPSFC3wGtXHH/2zo1uRhsH5hd+1P+lznFZ'

PICKLE_IN  = '/cowrie/cowrie-git/src/cowrie/data/fs.pickle'
PICKLE_OUT = '/cowrie/var/log/cowrie/fs_patched.pickle'

A_CONTENTS = 7
A_SIZE     = 4
A_TYPE     = 1
T_FILE     = 2

def patch_node(node):
    if not isinstance(node, list) or len(node) < 8:
        return 0
    patched = 0
    if node[A_TYPE] == T_FILE and isinstance(node[A_CONTENTS], bytes):
        orig = node[A_CONTENTS]
        new  = orig.replace(OLD_KEY, NEW_KEY).replace(OLD_SECRET, NEW_SECRET)
        if new != orig:
            node[A_CONTENTS] = new
            node[A_SIZE]     = len(new)
            name = node[0].decode() if isinstance(node[0], bytes) else node[0]
            print(f'  patched: {name}')
            patched += 1
    if isinstance(node[A_CONTENTS], list):
        for child in node[A_CONTENTS]:
            patched += patch_node(child)
    return patched

with open(PICKLE_IN, 'rb') as f:
    fs = pickle.load(f)

# fs IS the root directory entry (not a list of entries) — call directly
total = patch_node(fs)
print(f'Total files patched: {total}')

with open(PICKLE_OUT, 'wb') as f:
    pickle.dump(fs, f)
print(f'Saved to {PICKLE_OUT}')
