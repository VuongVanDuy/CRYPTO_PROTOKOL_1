from . import UDPClient, load_key_from_file
from SecureCommClient.hybird_encrypt import HybirdEncryption

if __name__ == "__main__":
    # Load RSA keys from files
    private_key_pem_Bob = load_key_from_file("keys/bob_private.pem")
    public_key_pem_Alice = load_key_from_file("keys/alice_public.pem")
    privateSign_key_pem_Bob = load_key_from_file("keys/bob_sign_private.pem")
    publicSign_key_pem_Alice = load_key_from_file("keys/alice_sign_public.pem")

    Bob_handler = HybirdEncryption.add_keys(
        private_key_pem_Alice=private_key_pem_Bob,
        public_key_pem_Bob=public_key_pem_Alice,
        privateSign_key_pem_Alice=privateSign_key_pem_Bob,
        publicSign_key_pem_Bob=publicSign_key_pem_Alice
    )

    client = UDPClient(host="127.0.0.1", port_listen=9998, port_send=9999, kernel_encryption=Bob_handler)
    client.client_listen()