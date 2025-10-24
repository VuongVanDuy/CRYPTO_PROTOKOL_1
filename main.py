import threading

from pynput.keyboard import Key, Listener
import requests
import socket
from typing import Optional
from SecureCommClient import UDPClient
from SecureCommClient import HybirdEncryption
from interface import ConsoleMenu
from Crypto.rsapkg import generateKeyPair, RsaKeyPair
from config import *
from untils import load_key_from_file, save_key_to_file, loadCertPublicKeyPem, format_pem

class MainApp:
    def __init__(self, console_menu: ConsoleMenu):
        self.console_menu = console_menu
        self.private_key_pem_Alice: Optional[str] = None
        self.public_key_pem_Alice: Optional[str] = None
        self.private_sign_key_pem_Alice: Optional[str] = None
        self.public_sign_key_pem_Alice: Optional[str] = None
        self.cert_pem_Alice: Optional[str] = None
        self.cert_pem_Bob: Optional[str] = None
        self.is_verified: bool = False
        self.udp_client: Optional[UDPClient] = None
        self.running: bool = True
        self.FLAG_ACTIVE = False
        self.listener = None
        self.buffer = ""
        self.load_existing_keys()

    def load_existing_keys(self):
        self.private_key_pem_Alice = load_key_from_file(ALICE_PRIVATE_KEY_PATH)
        self.public_key_pem_Alice = load_key_from_file(ALICE_PUBLIC_KEY_PATH)
        self.private_sign_key_pem_Alice = load_key_from_file(ALICE_SIGN_PRIVATE_KEY_PATH)
        self.public_sign_key_pem_Alice = load_key_from_file(ALICE_SIGN_PUBLIC_KEY_PATH)
        self.cert_pem_Alice = load_key_from_file(ALICE_CERT_PATH)
        self.cert_pem_Bob = load_key_from_file(BOB_CERT_PATH)

        if not all([self.private_key_pem_Alice, self.public_key_pem_Alice, self.private_sign_key_pem_Alice, self.public_sign_key_pem_Alice]):
            print("One or more keys could not be loaded from the specified paths.")

    def send_certificate(self, cert_pem: str):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(cert_pem.encode(), (HOST_BOB, PORT_SEND))

    def receive_certificate(self) -> str | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', PORT_LISTEN))
        sock.settimeout(10)

        while True:
            try:
                data, _ = sock.recvfrom(65535)
                sock.close()
                return data.decode()
            except socket.timeout:
                return None

    def execute_selection(self):
        option = self.console_menu.current_selection
        print(f"\nВыбранная опция: {self.console_menu.options[option]}")

        if option == 0:
            key_rsa_encrypt = generateKeyPair(bits=2048, e=65537)
            key_rsa_sign = generateKeyPair(bits=2048, e=65537)
            # save keys to files
            path1 = save_key_to_file(ALICE_PUBLIC_KEY_PATH, key_rsa_encrypt.to_public_pem())
            path2 = save_key_to_file(ALICE_SIGN_PRIVATE_KEY_PATH, key_rsa_sign.to_private_pem())
            path3 = save_key_to_file(ALICE_PRIVATE_KEY_PATH, key_rsa_encrypt.to_private_pem())
            path4 = save_key_to_file(ALICE_SIGN_PUBLIC_KEY_PATH, key_rsa_sign.to_public_pem())
            self.load_existing_keys()
            self.buffer = f"Keys generated and saved to:\n{path1}\n{path2}\n{path3}\n{path4}\n"

        if option == 1:
            if not all([self.private_key_pem_Alice, self.public_key_pem_Alice, self.private_sign_key_pem_Alice, self.public_sign_key_pem_Alice]):
                self.buffer = "Keys are not loaded. Please generate keys first.\n"
            else:
                data = {
                    "subject": SUBJECT,
                    "subject_public_encrypt_pem": format_pem(self.public_key_pem_Alice),
                    "subject_public_sign_pem": format_pem(self.public_sign_key_pem_Alice)
                }
                response = requests.post(f"{HOST_CA_SERVER}/cert/issue", json=data)
                if response.status_code == 200:
                    cert_pem = response.json().get("certificate_pem", "")
                    self.cert_pem_Alice = cert_pem
                    with open(ALICE_CERT_PATH, "w") as cert_file:
                        cert_file.write(cert_pem)
                    self.buffer = f"Certificate received and saved to {ALICE_CERT_PATH}\n"
                else:
                    self.buffer = f"Failed to obtain certificate: {response.text}\n"

        if option == 2:
            if not self.cert_pem_Alice:
                self.buffer = "Certificate not loaded. Please obtain a certificate first.\n"
            else:
                self.send_certificate(self.cert_pem_Alice)
                self.buffer = "Certificate sent to Bob.\n"
                cert_bob_pem = self.receive_certificate()
                if cert_bob_pem:
                    with open(BOB_CERT_PATH, "w") as cert_file:
                        cert_file.write(cert_bob_pem)
                    self.buffer += f"Certificate received from Bob and saved to {BOB_CERT_PATH}\n"
                else:
                    self.buffer += "No certificate received from Bob.\n"

        if option == 3:
            data = {
                "certificate_pem": format_pem(self.cert_pem_Bob)
            }
            response = requests.post(f"{HOST_CA_SERVER}/cert/verify", json=data)
            if response.status_code == 200:
                result = response.json().get("ok", False)
                self.buffer = "Certificate is valid.\n" if result else "Certificate is invalid.\n"
                # generate UDPClient for further communication if verified
                if result:
                    self.is_verified = True
                    # decode Bob's certificate to extract public keys
                    (n1, e1), (n2, e2) = loadCertPublicKeyPem(pem=self.cert_pem_Bob)
                    public_key_pem_Bob = RsaKeyPair(n=n1, e=e1).to_public_pem()
                    public_sign_key_pem_Bob = RsaKeyPair(n=n2, e=e2).to_public_pem()

                    kernel_encryption = HybirdEncryption.add_keys(
                        private_key_pem_Alice=self.private_key_pem_Alice,
                        public_key_pem_Bob=public_key_pem_Bob,
                        privateSign_key_pem_Alice=self.private_sign_key_pem_Alice,
                        publicSign_key_pem_Bob=public_sign_key_pem_Bob
                    )
                    self.udp_client = UDPClient(
                        host=HOST_BOB,
                        port_send=PORT_SEND,
                        port_listen=PORT_LISTEN,
                        kernel_encryption=kernel_encryption
                    )
                    # Start listening in a separate thread or process as needed
                    #threading.Thread(target=self.udp_client.client_listen).start()
                    # self.udp_client.client_listen()
                    self.reset_running()
                    # self.stop_monitor()
            else:
                self.buffer = f"Failed to verify certificate: {response.text}\n"

        if option == 4:
            if self.is_verified and self.udp_client is not None:
                self.stop_monitor()
                message = input(f"Enter the message to send to {SUBJECT}: ")
                self.udp_client.send_message(message)
                self.buffer += f"Enter the message to send to {SUBJECT}:" + message + "\n"
                # self.buffer = "Encrypted message sent to Bob.\n"
                self.start_monitor()
            else:
                self.buffer = "Cannot send message. Certificate not verified or UDP client not initialized.\n"


    def show_console(self):
        self.console_menu.clear_screen()
        self.console_menu.draw_console(buffer=self.buffer)

    def on_press(self, key):
        try:
            if key == Key.up:
                self.console_menu.current_selection = (self.console_menu.current_selection - 1) % len(
                    self.console_menu.options)
            elif key == Key.down:
                self.console_menu.current_selection = (self.console_menu.current_selection + 1) % len(
                    self.console_menu.options)
            elif key == Key.enter:
                self.execute_selection()
            self.show_console()
        except AttributeError:
            pass

    def on_release(self, key):
        try:
            if key == Key.esc or not self.running:
                self.running = False
                return False
        except AttributeError:
            pass

    def start_monitor(self):
        if self.FLAG_ACTIVE:
            return

        self.listener = Listener(on_press=self.on_press, on_release=None)
        self.listener.start()
        self.FLAG_ACTIVE = True

    def stop_monitor(self):
        if not self.FLAG_ACTIVE:
            return
        if self.listener is not None:
            self.listener.stop()
            #self.listener.join(timeout=1.0)
            self.listener = None
        self.FLAG_ACTIVE = False

    def reset_running(self):
        self.stop_monitor()
        threading.Thread(target=self.start_session).start()
        self.udp_client.client_listen()
        self.buffer = ""

    def start_session(self):
        self.show_console()
        self.start_monitor()

    def run(self):
        self.show_console()
        self.start_monitor()

        try:
            # Giữ chương trình chạy
            while self.running:
                # Có thể thêm các tác vụ khác ở đây
                threading.Event().wait(0.1)  # Sleep ngắn để giảm CPU usage

        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            self.stop_monitor()

if __name__ == "__main__":
    console_menu = ConsoleMenu()
    app = MainApp(console_menu=console_menu)
    app.run()