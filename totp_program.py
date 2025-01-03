import base64
import struct
import time
from hashlib import sha1
import hmac

X = 30 # Time step in seconds

# the hotp creation func
def hotp(K: str, T: int):
    if isinstance(K, str):
        missing_padding = len(K) % 8
        if missing_padding:
            K += '=' * (8 - missing_padding)
        K = base64.b32decode(K, casefold=True)
    T = struct.pack('>Q', T)
    hmac_sha1 = hmac.new(K, T, sha1).digest()
    offset = hmac_sha1[-1] & 0xF
    part = struct.unpack(">I", hmac_sha1[offset:offset + 4])[0] & 0x7FFFFFFF
    code = part % (10 ** 6)
    return str(code).zfill(6)

# the totp creation func
def totp(K: str):
    T, T0 = 0, 0
    T = (int(time.time()) - T0) // X
    print(f"OTP: {hotp(K, T)}")

# The main endpoint, create thread
def main():
    K = input("Введите кодовую фразу: ") # Unique key
    try:
        base64.b32decode(K, casefold=True)
        print("Секретный ключ корректен")
    except Exception as e:
        print("Неподходящий секретный ключ")
        return
    totp(K)
    second = time.strftime("%S", time.gmtime())
    tic = abs(int(second)-30) if int(second) < 30 else abs(int(second)-60)
    while True:
        second = time.strftime("%S", time.gmtime())
        if second == "00" or second == "30":
            totp(K)
            tic = 30
        tic -= 1
        print(f"New OTP code after {tic} sec.")
        time.sleep(1)

if __name__ == "__main__":
    main()