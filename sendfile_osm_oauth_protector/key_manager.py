import os
import stat
import nacl.public
import nacl.signing


class KeyManager:
    """Manage all keys used to encrypt and sign the cookies."""

    def __init__(self, directory_name):
        self.directory_name = directory_name
        self.boxes = {}
        self.signing_keys = {}
        self.verify_keys = {}
        self._load_keys()

    def _flush_keys(self, name, encryption_keyfile, signing_keyfile, verify_keyfile):
        if encryption_keyfile is None or signing_keyfile is None or verify_keyfile is None:
            raise Exception("Some or all keys called " + name + " are missing.")
        #TODO catch exceptions
        with open(encryption_keyfile, "rb") as ekf:
            privkey = nacl.public.PrivateKey(ekf.read())
        pubkey = privkey.public_key
        self.boxes[name] = nacl.public.Box(privkey, pubkey)

        with open(signing_keyfile, "rb") as skf:
            self.signing_keys[name] = nacl.signing.SigningKey(skf.read())

        with open(verify_keyfile, "rb") as vkf:
            self.verify_keys[name] = nacl.signing.VerifyKey(vkf.read())

    def _load_keys(self):
        files = os.listdir(self.directory_name)
        files.sort()
        encryption_keyfile = None
        signing_keyfile = None
        verify_keyfile = None
        last_path_without_ext = None

        for entry in files:
            full_path = os.path.join(self.directory_name, entry)
            if entry.startswith(".") or stat.S_ISDIR(os.stat(full_path).st_mode):
                continue
            path, ext = os.path.splitext(entry)
            if path != last_path_without_ext and last_path_without_ext is not None:
                self._flush_keys(last_path_without_ext, encryption_keyfile, signing_keyfile, verify_keyfile)
                encryption_keyfile = None
                signing_keyfile = None
                verify_keyfile = None
            last_path_without_ext = path
            if ext == ".signkey":
                signing_keyfile = full_path
            elif ext == ".verifykey":
                verify_keyfile = full_path
            elif ext == ".encryptionkey":
                encryption_keyfile = full_path
        self._flush_keys(last_path_without_ext, encryption_keyfile, signing_keyfile, verify_keyfile)
