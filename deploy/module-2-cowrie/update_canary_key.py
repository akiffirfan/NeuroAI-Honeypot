import pickle

OLD_KEY_ID = b'AKIAQF3ZXVN2MPLR8KT4'
NEW_KEY_ID = b'AKIAYZM57LXRGIYTCOUV'
OLD_SECRET = b'gX7vL2mR9nK4wP8qY3jT6bZcF1sE0hA5uN2dW7eK'
NEW_SECRET = b'MpTqbycbuKX0q40aU5yCwCNtS2rWCzzH4cko/ptU'

def replace_in_fs(node):
    if isinstance(node, bytes):
        return node.replace(OLD_KEY_ID, NEW_KEY_ID).replace(OLD_SECRET, NEW_SECRET)
    elif isinstance(node, list):
        return [replace_in_fs(item) for item in node]
    elif isinstance(node, str):
        return node.replace(OLD_KEY_ID.decode(), NEW_KEY_ID.decode()).replace(OLD_SECRET.decode(), NEW_SECRET.decode())
    return node

with open('/cowrie/cowrie-git/src/cowrie/data/fs.pickle', 'rb') as f:
    fs = pickle.load(f)

fs = replace_in_fs(fs)

with open('/cowrie/var/log/cowrie/fs.pickle', 'wb') as f:
    pickle.dump(fs, f)

print('Canary key updated in fs.pickle')
