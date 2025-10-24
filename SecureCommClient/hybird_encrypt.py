from Crypto.despkg import DesCipher
from Crypto.rsapkg import Rsa
from dataclasses import dataclass
from typing import Dict, Any
import secrets


class SignatureError(Exception):
    pass

@dataclass
class HybirdEncryption:
    Rsa_private_Alice: Rsa
    Rsa_public_Bob: Rsa
    Rsa_privateSign_Alice: Rsa
    Rsa_publicSign_Bob: Rsa

    @staticmethod
    def add_keys(private_key_pem_Alice: str,
                 public_key_pem_Bob: str,
                 privateSign_key_pem_Alice: str,
                 publicSign_key_pem_Bob: str) -> "HybirdEncryption":

        Rsa_private_Alice = Rsa.from_private_pem(private_key_pem_Alice)
        Rsa_public_Bob = Rsa.from_public_pem(public_key_pem_Bob)
        Rsa_privateSign_Alice = Rsa.from_private_pem(privateSign_key_pem_Alice)
        Rsa_publicSign_Bob = Rsa.from_public_pem(publicSign_key_pem_Bob)

        return HybirdEncryption(Rsa_private_Alice=Rsa_private_Alice,
                                Rsa_public_Bob=Rsa_public_Bob,
                                Rsa_privateSign_Alice=Rsa_privateSign_Alice,
                                Rsa_publicSign_Bob=Rsa_publicSign_Bob)

    # generate a random DES session key
    def generate_des_key(self) -> bytes:
        return secrets.token_bytes(8)  # DES key is 8 bytes (64 bits)

    def create_digital_envelope(self, message: bytes) -> Dict[str, Any]:
        # Generate a random DES session key
        des_sesion_key = self.generate_des_key()

        # Encrypt the message using DES with ECB mode
        des_cipher = DesCipher()
        encrypted_message = des_cipher.encrypt(plaintext=message,
                                               key=des_sesion_key,
                                               mode="ECB")

        # Encrypt the DES session key using Bob's RSA public key
        encrypted_des_key = self.Rsa_public_Bob.encrypt(plaintext=des_sesion_key, padding="oaep")

        # Combine the encrypted DES key and the encrypted message
        combine_encrypted = encrypted_des_key + encrypted_message

        # Add signature using Alice's RSA private keySign
        signature = self.Rsa_privateSign_Alice.sign(message=combine_encrypted, padding="pss")

        # Return the encrypted DES key, encrypted message, and signature
        return {
            "encrypted_des_key": encrypted_des_key,
            "encrypted_message": encrypted_message,
            "signature": signature
        }

    def decrypt_received_digital_envelope(self, envelope: Dict[str, Any]) -> bytes:
        encrypted_des_key = envelope["encrypted_des_key"]
        encrypted_message = envelope["encrypted_message"]
        signature = envelope["signature"]

        # Verify the signature using Bob's RSA public keySign
        combine_encrypted = encrypted_des_key + encrypted_message
        if not self.Rsa_publicSign_Bob.verify(message=combine_encrypted,
                                              signature=signature,
                                              padding="pss"):
            raise SignatureError("Signature verification failed.")

        # Decrypt the DES session key using Alice's RSA private key
        des_sesion_key = self.Rsa_private_Alice.decrypt(ciphertext=encrypted_des_key, padding="oaep")

        # Decrypt the message using DES with ECB mode
        des_cipher = DesCipher()
        decrypted_message = des_cipher.decrypt(ciphertext=encrypted_message,
                                               key=des_sesion_key,
                                               mode="ECB")

        return decrypted_message

if __name__ == "__main__":
    # Example usage
    from Crypto.rsapkg import Rsa
    # Generate keys for Alice and Bob
    alice_rsa = Rsa.generate(bits=2048)
    bob_rsa = Rsa.generate(bits=2048)
    alice_sign_rsa = Rsa.generate(bits=2048)
    bob_sign_rsa = Rsa.generate(bits=2048)

    Alice = HybirdEncryption.add_keys(
        private_key_pem_Alice=alice_rsa.to_private_pem(),
        public_key_pem_Bob=bob_rsa.to_public_pem(),
        privateSign_key_pem_Alice=alice_sign_rsa.to_private_pem(),
        publicSign_key_pem_Bob=bob_sign_rsa.to_public_pem()
    )

    Bob = HybirdEncryption.add_keys(
        private_key_pem_Alice=bob_rsa.to_private_pem(),
        public_key_pem_Bob=alice_rsa.to_public_pem(),
        privateSign_key_pem_Alice=bob_sign_rsa.to_private_pem(),
        publicSign_key_pem_Bob=alice_sign_rsa.to_public_pem()
    )

    # Alice sends an encrypted message to Bob
    message = b"Hello Bob, this is a secret message from Alice."
    envelope = Alice.create_digital_envelope(message=message)
    print(envelope)

    # Bob receives and decrypts the message
    decrypted_message = Bob.decrypt_received_digital_envelope(envelope=envelope)
    print("Decrypted message from Alice:", decrypted_message.decode("utf-8"))

    # Bob sends an encrypted message to Alice
    reply_message = b"Hello Alice, I received your secret message."
    reply_envelope = Bob.create_digital_envelope(message=reply_message)
    print(reply_envelope)
    # Alice receives and decrypts the message
    decrypted_reply_message = Alice.decrypt_received_digital_envelope(envelope=reply_envelope)
    print("Decrypted message from Bob:", decrypted_reply_message.decode("utf-8"))
