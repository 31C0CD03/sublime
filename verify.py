from pprint import pprint
from dataclasses import dataclass, asdict

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1


key = """-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDYe6JFYvfF0UoM+xK5dAwZXGvc
fm1uySusDrKdWeHZrmeJDCuIw6vcr/59SjPcwb++UxolHO8Mkj8GvnmyMoVZrP7p
htXhXk0XZupWxOEGV/p02wl3w/t1greM1Huyx/myUrSpRj0V9q5u6SN9VMVIG/Pg
sJkgGQvPsx5b5QnDOwIBEQ==
-----END PUBLIC KEY-----"""

@dataclass
class License:
    user: str
    meta: str
    id: str
    sig: str

    @classmethod
    def parse(cls, license):
        lines = license.strip().split("\n")
        assert len(lines) == 13
        assert lines[0] == "----- BEGIN LICENSE -----"
        assert lines[12] == "------ END LICENSE ------"
        user = lines[1].strip()
        meta = lines[2].strip()
        id = lines[3].strip()
        sig = "".join(lines[4:12]).replace(" ", "")
        return cls(user, meta, id, sig)
    
    def verify(self):
        public_key = RSA.import_key(key)
        data = f"{self.user}\n{self.meta}\n{self.id}".encode()
        sig = bytes.fromhex(self.sig)
        hasher = SHA1.new(data)
        try:
            pkcs1_15.new(public_key).verify(hasher, sig)
            return True;
        except (ValueError, TypeError):
            return False;



with open("sample.txt") as f:
    license = License.parse(f.read())
    pprint(asdict(license), sort_dicts=False)
    print("valid signature" if license.verify() else "invalid signature")