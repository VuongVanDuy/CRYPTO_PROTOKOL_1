KEY_DIRS = "./data/keys"
ALICE_PRIVATE_KEY_PATH = f"{KEY_DIRS}/alice_private.pem"
ALICE_PUBLIC_KEY_PATH = f"{KEY_DIRS}/alice_public.pem"
#BOB_PUBLIC_KEY_PATH = f"{KEY_DIRS}/bob_public.pem"
ALICE_SIGN_PRIVATE_KEY_PATH = f"{KEY_DIRS}/alice_sign_private.pem"
# BOB_SIGN_PUBLIC_KEY_PATH = f"{KEY_DIRS}/bob_sign_public.pem"
ALICE_SIGN_PUBLIC_KEY_PATH = f"{KEY_DIRS}/alice_sign_public.pem"

CERT_DIRS = "./data/certs"
ALICE_CERT_PATH = f"{CERT_DIRS}/alice.crt"
BOB_CERT_PATH = f"{CERT_DIRS}/bob.crt"

HOST_BOB = "10.0.2.15"
PORT_LISTEN = 5001
PORT_SEND = 5000
SUBJECT = "Bob"
HOST_CA_SERVER = "http://198.18.0.1:8000"