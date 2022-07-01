# copy pasta of pyethereum
# https://github.com/ethereum/pyethereum/blob/782842758e219e40739531a5e56fff6e63ca567b/ethereum/utils.py
# use version 3 of python and > v6 for rlp
try:
    from Crypto.Hash import keccak
    sha3_256 = lambda x: keccak.new(digest_bits=256, data=x).digest()
except:
    import sha3 as _sha3
    sha3_256 = lambda x: _sha3.sha3_256(x).digest()
from rlp.utils import decode_hex, encode_hex, ascii_chr, str_to_bytes
import rlp

# assumes python3
def to_string(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return bytes(value, 'utf-8')
    if isinstance(value, int):
        return bytes(str(value), 'utf-8')

def sha3(seed):
    return sha3_256(to_string(seed))

def normalize_address(x, allow_blank=False):
    if allow_blank and x == '':
        return ''
    if len(x) in (42, 50) and x[:2] == '0x':
        x = x[2:]
    if len(x) in (40, 48):
        x = decode_hex(x)
    if len(x) == 24:
        assert len(x) == 24 and sha3(x[:20])[:4] == x[-4:]
        x = x[:20]
    if len(x) != 20:
        raise Exception("Invalid address format: %r" % x)
    return x

def decode_addr(v):
    '''decodes an address from serialization'''
    if len(v) not in [0, 20]:
        raise Exception("Serialized addresses must be empty or 20 bytes long!")
    return encode_hex(v)

def mk_contract_address(sender, nonce):
    a = rlp.encode([normalize_address(sender), nonce])
    return sha3(a)[12:]

# npx hardhat accounts
# private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
sender = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
nonce = 0
print(' '* 51 + decode_addr(mk_contract_address(sender, nonce)))
print("This exists already https://etherscan.io/address/0x5fbdb2315678afecb367f032d93f642f64180aa3")

# this appears to be an EOA and NOT a smart contract.
# before you get any crazy ideas, you can't steal the funds because the nonce for that account
# is not zero anymore. But still, the chances of this happening are stupidly slim...
