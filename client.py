import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
from crypto_utils import (
    generate_session_key, rsa_encrypt_session_key, rsa_decrypt_session_key,
    derive_chacha_key, chacha_encrypt, chacha_decrypt,
    public_key_to_bytes, bytes_to_public_key,
    load_private_key, load_public_key
)


class ChatClient:
    # تهيئة إعدادات العميل وبناء الواجهة
    def __init__(self, host="127.0.0.1", port=9999):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.chacha_key = None
        self.session_key = None
        self.peer_public_key = None
        self.private_key = None
        self.public_key = None
        self.client_name = None
        self.build_gui()


    # إنشاء نافذة المحادثة وأدوات التحكم
    def build_gui(self):
        self.root = tk.Tk()
        self.root.title("Secure Chat Client")
        self.root.geometry("600x500")

        self.chat_area = scrolledtext.ScrolledText(
            self.root,
            width=70,
            height=22,
            state=tk.DISABLED
        )
        self.chat_area.pack(padx=10, pady=10)

        self.top_frame = tk.Frame(self.root)
        self.top_frame.pack(pady=5)

        self.connect_button = tk.Button(
            self.top_frame,
            text="Connect",
            bg="green",
            fg="white",
            command=self.connect_to_server
        )
        self.connect_button.pack(side=tk.LEFT, padx=10)

        self.disconnect_button = tk.Button(
            self.top_frame,
            text="Disconnect",
            bg="red",
            fg="white",
            state=tk.DISABLED,
            command=self.disconnect
        )
        self.disconnect_button.pack(side=tk.LEFT, padx=10)

        self.status_label = tk.Label(
            self.root,
            text="Status: Disconnected",
            fg="red"
        )
        self.status_label.pack(pady=5)

        self.bottom_frame = tk.Frame(self.root)
        self.bottom_frame.pack(fill=tk.X, padx=10, pady=5)

        self.message_entry = tk.Entry(self.bottom_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.message_entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(
            self.bottom_frame,
            text="Send",
            command=self.send_message
        )
        self.send_button.pack(side=tk.RIGHT, padx=5)


    # إضافة رسالة إلى منطقة المحادثة
    def log(self, sender, message):
        full_message = "[" + sender + "]: " + str(message) + "\n"
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, full_message)
        self.chat_area.see(tk.END)
        self.chat_area.config(state=tk.DISABLED)


    # الاتصال بالخادم وتحميل مفاتيح العميل
    def connect_to_server(self):
        if self.running:
            return

        try:
            answer = simpledialog.askstring(
                "Client name",
                "Are you ClientA or ClientB?"
            )

            if answer is None:
                return

            answer = answer.upper()

            if answer == "A":
                self.client_name = "A"
                self.private_key = load_private_key(
                    "keys/clientA_private.pem"
                )
                self.public_key = load_public_key(
                    "keys/clientA_public.pem"
                )
            elif answer == "B":
                self.client_name = "B"
                self.private_key = load_private_key(
                    "keys/clientB_private.pem"
                )
                self.public_key = load_public_key(
                    "keys/clientB_public.pem"
                )
            else:
                messagebox.showwarning(
                    "Warning",
                    "Please enter A or B."
                )
                return

            if self.private_key is None or self.public_key is None:
                messagebox.showerror(
                    "Error",
                    "Could not load the selected client keys."
                )
                return

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.running = True

            own_pub_bytes = public_key_to_bytes(self.public_key)
            self.send_data(b"PUBLIC_KEY:" + own_pub_bytes)

            receive_thread = threading.Thread(
                target=self.receive_loop,
                daemon=True
            )
            receive_thread.start()

            self.status_label.config(text="Status: Connected", fg="green")
            self.connect_button.config(state=tk.DISABLED)
            self.disconnect_button.config(state=tk.NORMAL)
            self.log("System", "Connected to server")
        except Exception as error:
            print("Connection error:", error)
            self.running = False
            if self.socket is not None:
                self.socket.close()
                self.socket = None
            messagebox.showerror("Error", "Could not connect to server.")


    # إرسال بيانات مع طولها في بداية الرسالة
    def send_data(self, data):
        message_length = len(data).to_bytes(4, "big")
        self.socket.sendall(message_length + data)


    # استقبال عدد محدد من البايتات
    def receive_exact(self, n):
        data = b""

        while len(data) < n:
            part = self.socket.recv(n - len(data))

            if not part:
                return b""

            data = data + part

        return data


    # استقبال البيانات من الخادم ومعالجتها
    def receive_loop(self):
        try:
            while self.running:
                length_data = self.receive_exact(4)

                if not length_data:
                    break

                message_length = int.from_bytes(length_data, "big")
                data = self.receive_exact(message_length)

                if not data:
                    break

                self.process_message(data)
        except Exception as error:
            if self.running:
                print("Receive error:", error)
        finally:
            self.disconnect()


    # معالجة المفتاح العام ومفتاح الجلسة والرسائل المشفرة
    def process_message(self, data):
        if data.startswith(b"PUBLIC_KEY:"):
            key_data = data[len(b"PUBLIC_KEY:"):]
            self.peer_public_key = bytes_to_public_key(key_data)

            if self.peer_public_key is None:
                self.log("System", "Could not read peer public key")
                return

            self.log("System", "Peer public key received")

            if self.client_name == "A":
                self.session_key = generate_session_key()
                encrypted_key = rsa_encrypt_session_key(
                    self.peer_public_key,
                    self.session_key
                )
                self.send_data(b"SESSION_KEY:" + encrypted_key)
                self.chacha_key = derive_chacha_key(self.session_key)
                self.log("System", "Encryption established")

        elif data.startswith(b"SESSION_KEY:"):
            encrypted_key = data[len(b"SESSION_KEY:"):]
            self.session_key = rsa_decrypt_session_key(
                self.private_key,
                encrypted_key
            )
            self.chacha_key = derive_chacha_key(self.session_key)
            self.log("System", "Encryption established")
        else:
            if self.chacha_key is None:
                self.log("System", "Encrypted message received too early")
                return

            nonce = data[:12]
            ciphertext = data[12:]
            plaintext = chacha_decrypt(
                self.chacha_key,
                nonce,
                ciphertext
            )
            self.log("Peer", plaintext.decode("utf-8"))


    # تشفير الرسالة وإرسالها إلى العميل الآخر
    def send_message(self, event=None):
        if not self.running or self.chacha_key is None:
            messagebox.showwarning(
                "Warning",
                "Connect and wait for encryption to be established."
            )
            return

        text = self.message_entry.get()

        if text == "":
            return

        try:
            plaintext = text.encode("utf-8")
            nonce, ciphertext = chacha_encrypt(
                self.chacha_key,
                plaintext
            )
            self.send_data(nonce + ciphertext)
            self.log("Me", text)
            self.message_entry.delete(0, tk.END)
        except Exception as error:
            print("Send error:", error)
            messagebox.showerror("Error", "Could not send message.")


    # قطع الاتصال وتحديث حالة الواجهة
    def disconnect(self):
        was_running = self.running
        self.running = False

        if self.socket is not None:
            try:
                self.socket.close()
            except Exception as error:
                print("Disconnect error:", error)
            self.socket = None

        self.status_label.config(text="Status: Disconnected", fg="red")
        self.connect_button.config(state=tk.NORMAL)
        self.disconnect_button.config(state=tk.DISABLED)

        if was_running:
            self.log("System", "Disconnected")


    # تشغيل حلقة واجهة Tkinter
    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    client = ChatClient()
    client.run()
