import base64
from Crypto.rsapkg.keys import generateKeyPair
from Crypto.rsapkg.pem import savePrivateKeyPem, savePublicKeyPem
from Crypto.rsapkg.rsa_core import rsaEncrypt, rsaDecrypt, rsaSign, rsaVerify

def main():
    kp = generateKeyPair(bits=1024)
    priv_pem = savePrivateKeyPem(kp)
    pub_pem = savePublicKeyPem(kp.n, kp.e)
    print(priv_pem)
    print(pub_pem)

    msg = b"hello rsa"
    ct = rsaEncrypt(msg, kp.n, kp.e, padding="oaep")
    print("cipher (b64):", base64.b64encode(ct).decode())

    pt = rsaDecrypt(ct, kp.n, kp.d, padding="oaep")
    print("plain:", pt)

    sig = rsaSign(msg, kp.n, kp.d, padding="pss")
    print("sig (b64):", base64.b64encode(sig).decode())

    print("verify:", rsaVerify(msg, sig, kp.n, kp.e, padding="pss"))

if __name__ == "__main__":
    main()