import hashlib
import ecdsa
import base58
import bech32
from ecdsa.numbertheory import inverse_mod
from ecdsa.ecdsa import generator_secp256k1

# ✅ Dane z pierwszej transakcji
r1 = int("ced8474e7cbb2c9ade8b4a6474c3fa8ea4036718d844f3105dde155a6583a134", 16)
s1 = int("1c9e070de661d5913d457c6f075641ec28c8c8f4fe336070710787e471ebd558  ", 16)
z1 = int("0cf7190cc6c1f95b987e0e284e4eba44552f89662272b850b059a8dc0d8905a8   ", 16)

# ✅ Dane z drugiej transakcji
r2 = int("ceda0e7cfe7e6da20b3e1b08877e722eceba96574f50b78c8b03618e4c6ce18c", 16)
s2 = int("034a6987bc4e6cfac6a8a5ed767ccbbf47cfb15323b3ebb44f3e72ee6148e255", 16)
z2 = int("e204e6d82b618ec35cbb3d0c902d76a00d4afa6cfbb37e797309a73a0b5ddb55", 16)

# ✅ Stała wartość krzywej secp256k1 (order n)
n = generator_secp256k1.order()

# ✅ **Obliczenie `k`**
delta_s = (s1 - s2) % n
delta_z = (z1 - z2) % n

if delta_s != 0:
    k = (delta_z * inverse_mod(delta_s, n)) % n
    print(f"✅ Wykryto liniową zależność k! k = {hex(k)}")
else:
    print("❌ Brak liniowej zależności w k")
    exit()

# ✅ **Obliczenie klucza prywatnego `d`**
d = ((s1 * k - z1) * inverse_mod(r1, n)) % n

print("\n🚀 🔥 **Obliczone wartości:**")
print(f"🔹 r  = {hex(r1)}")
print(f"🔹 s  = {hex(s1)}")
print(f"🔹 z  = {hex(z1)}")
print(f"🔹 k  = {hex(k)}")
print(f"🔹 d  = {hex(d)}")

def generate_addresses_from_private_key(d):
    """ Konwersja klucza prywatnego na różne formaty adresów """
    G = ecdsa.SigningKey.from_secret_exponent(d, curve=ecdsa.SECP256k1).verifying_key
    pubkey = b'\x04' + G.to_string()

    # ✅ P2WPKH (Bech32 bc1...)
    pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
    bech32_address = bech32.encode("bc", 0, pubkey_hash)

    # ✅ Nested SegWit (P2SH-P2WPKH 3...)
    nested_script = b'\x00\x14' + pubkey_hash  # OP_0 + PUSH(20) + pubkey hash
    nested_hash = hashlib.new('ripemd160', hashlib.sha256(nested_script).digest()).digest()
    nested_p2sh = base58.b58encode_check(b'\x05' + nested_hash).decode()

    return bech32_address, nested_p2sh

# ✅ Generujemy adresy z `d`
bech32_addr, nested_p2sh_addr = generate_addresses_from_private_key(d)

# ✅ Oczekiwane adresy
expected_p2sh = "3C9fjvRDGc1VK2hKJ6EVFBMc65Nc463dUV"
expected_bech32 = "bc1qlsmt5a8vqqus5fwslx8pyyemgjtg4y6uuvsgzg"

print("\n🚀 ✅ **Obliczone adresy:**")
print(f"🔹 Obliczony adres Bech32: {bech32_addr}")
print(f"🔹 Obliczony Nested P2SH: {nested_p2sh_addr}")
print(f"📌 Oczekiwany P2SH: {expected_p2sh}")
print(f"📌 Oczekiwany Bech32: {expected_bech32}")

# ✅ Sprawdzamy, czy adresy pasują
if expected_p2sh == nested_p2sh_addr and expected_bech32 == bech32_addr:
    print("\n✅ 🔥 Klucz prywatny pasuje do obu adresów! To ten sam właściciel!")
else:
    print("\n❌ Adresy nie pasują! Możliwe, że P2SH było multisig lub inny typ skryptu.")
