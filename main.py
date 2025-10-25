import threading
from pynput.keyboard import Key, Listener
import requests
import socket
import json
import time
from typing import Optional
from SecureCommClient import UDPClient, SignatureError, HybirdEncryption
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
        self.flag_1: bool = True
        self.flag_2: bool = False
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

    def handshake_certificate(self, cert_pem: str) -> str | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', PORT_LISTEN))
        sock.settimeout(1)
        signal_Alice = 'not received'
        cert_received = None

        while True:
            try:
                print("sent to bob..")
                data = {"signal": signal_Alice, "cert_pem": cert_pem}
                sent = sock.sendto(json.dumps(data).encode(), (HOST_BOB, PORT_SEND))
                try:
                    data, _ = sock.recvfrom(65535)
                except socket.timeout:
                    continue

                try:
                    data = json.loads(data.decode())
                except json.JSONDecodeError as e:
                    sock.close()
                    return None

                cert_received = data['cert_pem']
                signal_Bob = data['signal']

                if cert_received:
                    signal_Alice = 'received'

                if cert_received and signal_Bob == 'received':
                    data = {"signal": signal_Alice, "cert_pem": cert_pem}
                    sock.sendto(json.dumps(data).encode(), (HOST_BOB, PORT_SEND))
                    sock.close()
                    return cert_received
                
            except Exception as e:
                print(e)
                sock.close()
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
                self.buffer = "Certificate sent to Bob.\n"
                cert_bob_pem = self.handshake_certificate(self.cert_pem_Alice)
                if cert_bob_pem:
                    with open(BOB_CERT_PATH, "w") as cert_file:
                        cert_file.write(cert_bob_pem)
                    self.buffer += f"Certificate received from Bob and saved to {BOB_CERT_PATH}\n"
                else:
                    self.buffer += "No certificate received from Bob.\n"

        if option == 3:
            data = {
                "certificate_pem": self.cert_pem_Bob
            }
            response = requests.post(f"{HOST_CA_SERVER}/cert/verify", json=data)
            if response.status_code == 200:
                result = response.json().get("ok", False)
                print(result)
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
            
                    self.stop_monitor()
                    self.flag_1 = False
                    self.flag_2 = True
                    self.run_session_2()
            else:
                self.buffer = f"Failed to verify certificate: {response.text}\n"


    def show_console(self, session: int = 1):
        self.console_menu.clear_screen()
        self.console_menu.draw_console(session=session, buffer=self.buffer)

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
            if key == Key.esc:
                return False
        except AttributeError:
            return False
        except KeyboardInterrupt:
            return False

    def start_monitor(self):
        self.listener = Listener(on_press=self.on_press, on_release=self.on_release)
        self.listener.start()
        # self.FLAG_ACTIVE = True

    def stop_monitor(self):
        if self.listener is not None:
            self.listener.stop()
            #self.listener.join(timeout=1.0)
            self.listener = None
        # self.FLAG_ACTIVE = False


    def run_session_1(self):
        self.show_console()
        self.start_monitor()

        try:
            # Giữ chương trình chạy
            while True:
                # Có thể thêm các tác vụ khác ở đây
                threading.Event().wait(0.1)  # Sleep ngắn để giảm CPU usage

        except KeyboardInterrupt:
            print("\nShutting down...")
            self.stop_monitor()
        finally:
            self.stop_monitor()

    def loop_send_message(self):
        try:
            while True:
                message = input()
                if message.strip() and message.strip() != '\n':
                    self.udp_client.send_message(message)
                    self.buffer = f"You (Alice): {message}\n" + self.buffer
                self.show_console(session=2)
        except Exception as e:
            print(f"Error sending message in thread: {e}")

    def run_session_2(self):
        self.buffer = "Enter your message ->:"
        self.show_console(session=2)

        start_monitor_thread = threading.Thread(target=self.loop_send_message)
        start_monitor_thread.start()

        self.udp_client.socket.bind(('0.0.0.0', self.udp_client.port_listen))

        try:
            while self.flag_2:
                try:
                    received_data = self.udp_client.receive_message()
                    if received_data.strip():
                        self.buffer = f'Bob: {received_data}\n' + self.buffer
                        self.show_console(session=2)
                except socket.timeout:
                    continue
                except SignatureError as e:
                    self.buffer = f"Error: {e}" + self.buffer
                    self.show_console(session=2)
                    
        except Exception as e:
            print(f"Error receiving message: {e}")
        except KeyboardInterrupt:
            print("Interrupted by user.")
        finally:
            self.close()
            if start_monitor_thread.is_alive():
                start_monitor_thread.join(0.1)
            print("Socket closed.")


if __name__ == "__main__":
    console_menu = ConsoleMenu()
    app = MainApp(console_menu=console_menu)
    app.run_session_1()
