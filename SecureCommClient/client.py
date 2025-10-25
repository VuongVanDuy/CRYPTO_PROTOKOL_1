from SecureCommClient import HybirdEncryption, SignatureError
import json
import socket
import threading

class UDPClient:
    """
    UDP client để gửi và nhận thông điệp mã hóa theo dạng 'digital envelope'.
    Không cần thiết lập kết nối (connectionless), mỗi lần gửi là một datagram riêng biệt.
    """

    def __init__(self, host: str, port_listen: int, port_send: int, kernel_encryption: HybirdEncryption):
        self.host = host
        self.port_listen = port_listen
        self.post_send = port_send
        self.kernel_encryption = kernel_encryption
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.settimeout(2.0)  # tránh treo vĩnh viễn khi không có phản hồi

    def send_message(self, message: str):
        """Mã hóa và gửi thông điệp tới server qua UDP."""
        envelope = self.kernel_encryption.create_digital_envelope(message.encode())
        serialized_envelope = json.dumps({
            "encrypted_des_key": envelope["encrypted_des_key"].hex(),
            "encrypted_message": envelope["encrypted_message"].hex(),
            "signature": envelope["signature"].hex()
        }).encode()
        self.socket.sendto(serialized_envelope, (self.host, self.post_send))
        print(f"Sent {len(serialized_envelope)} bytes to {self.host}:{self.post_send}")

    def receive_message(self, buffer_size: int = 8192) -> str:
        """Nhận và giải mã thông điệp từ server qua UDP."""
        received_data, addr = self.socket.recvfrom(buffer_size)  # buffer size
        print(f"Received {len(received_data)} bytes from {addr}")

        envelope_dict = json.loads(received_data.decode())
        envelope = {
            "encrypted_des_key": bytes.fromhex(envelope_dict["encrypted_des_key"]),
            "encrypted_message": bytes.fromhex(envelope_dict["encrypted_message"]),
            "signature": bytes.fromhex(envelope_dict["signature"])
        }
        decrypted_message = self.kernel_encryption.decrypt_received_digital_envelope(envelope)
        return decrypted_message.decode(errors="replace")


    def close(self):
        """Đóng socket UDP."""
        self.socket.close()

    def loop_send_message(self):
        """Gửi thông điệp trong một luồng riêng biệt."""
        try:
            while True:
                message = input("Enter message to send (or 'exit' to quit):")
                try:
                  self.send_message(message)
                except socket.timeout:
                  continue
        except Exception as e:
            print(f"Error sending message in thread: {e}")

    def loop_receive_client(self, buffer_size: int = 8192):
        """Vòng lặp gửi/nhận tương tác từ bàn phím."""
        self.socket.bind(('0.0.0.0', self.port_listen))
        thread_loop_send = threading.Thread(target=self.loop_send_message)
        thread_loop_send.start()
        print(f"UDP client ready to send to {self.host}:{self.post_send} and receive on port {self.port_listen}")

        try:
            while True:
                try:
                    received_data, addr = self.socket.recvfrom(buffer_size)
                except socket.timeout:
                    continue
                print(f"Received {len(received_data)} bytes from {addr}")

                envelope_dict = json.loads(received_data.decode())
                envelope = {
                    "encrypted_des_key": bytes.fromhex(envelope_dict["encrypted_des_key"]),
                    "encrypted_message": bytes.fromhex(envelope_dict["encrypted_message"]),
                    "signature": bytes.fromhex(envelope_dict["signature"])
                }
                try:
                    decrypted_message = self.kernel_encryption.decrypt_received_digital_envelope(envelope)
                    print("Decrypted message:", decrypted_message.decode(errors="replace"))
                except SignatureError as se:
                    print(se)
        except Exception as e:
            print(f"Error receiving message: {e}")
        except KeyboardInterrupt:
            print("Interrupted by user.")
        finally:
            self.close()
            if thread_loop_send.is_alive():
                thread_loop_send.join(0.1)
            print("Socket closed.")
