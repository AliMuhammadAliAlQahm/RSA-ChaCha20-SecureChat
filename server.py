import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
import datetime


class ChatServer:
    # تهيئة إعدادات الخادم وبناء الواجهة
    def __init__(self, host="127.0.0.1", port=9999):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}
        self.running = False
        self.build_gui()


    # إنشاء نافذة الخادم وأزرار التحكم
    def build_gui(self):
        self.root = tk.Tk()
        self.root.title("Secure Chat Server")
        self.root.geometry("600x500")

        self.log_area = scrolledtext.ScrolledText(
            self.root,
            width=70,
            height=25,
            state=tk.DISABLED
        )
        self.log_area.pack(padx=10, pady=10)

        self.status_label = tk.Label(
            self.root,
            text="Status: Stopped",
            fg="red"
        )
        self.status_label.pack(pady=5)

        self.start_button = tk.Button(
            self.root,
            text="Start Server",
            bg="green",
            fg="white",
            command=self.start_server
        )
        self.start_button.pack(side=tk.LEFT, padx=100, pady=10)

        self.stop_button = tk.Button(
            self.root,
            text="Stop Server",
            bg="red",
            fg="white",
            state=tk.DISABLED,
            command=self.stop_server
        )
        self.stop_button.pack(side=tk.RIGHT, padx=100, pady=10)


    # إضافة رسالة مع الوقت إلى منطقة السجل
    def log(self, message):
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        full_message = "[" + current_time + "] " + message + "\n"

        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, full_message)
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)


    # إنشاء socket وتشغيل الخادم
    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1
            )
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(2)

            self.running = True
            self.status_label.config(text="Status: Running", fg="green")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

            self.log("Server started on " + self.host + ":" + str(self.port))

            accept_thread = threading.Thread(
                target=self.accept_clients,
                daemon=True
            )
            accept_thread.start()
        except Exception as error:
            self.log("Could not start server: " + str(error))
            self.running = False
            if self.server_socket is not None:
                self.server_socket.close()
                self.server_socket = None


    # إيقاف الخادم وإغلاق كل اتصالات العملاء
    def stop_server(self):
        self.running = False

        for client_socket in list(self.clients):
            try:
                client_socket.close()
            except Exception as error:
                print("Error closing client socket:", error)

        self.clients.clear()

        if self.server_socket is not None:
            try:
                self.server_socket.close()
            except Exception as error:
                print("Error closing server socket:", error)
            self.server_socket = None

        self.status_label.config(text="Status: Stopped", fg="red")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log("Server stopped")


    # انتظار اتصالات العملاء الجديدة
    def accept_clients(self):
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                self.clients[client_socket] = address
                self.log("New client connected from " + str(address))

                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket,),
                    daemon=True
                )
                client_thread.start()
            except Exception as error:
                if self.running:
                    self.log("Error accepting client: " + str(error))
                break


    # قراءة الرسائل المشفرة من العميل وتمريرها إلى العملاء الآخرين
    def handle_client(self, client_socket):
        try:
            while self.running:
                length_data = client_socket.recv(4)

                if not length_data:
                    break

                if len(length_data) != 4:
                    break

                message_length = int.from_bytes(length_data, byteorder="big")
                data = b""

                while len(data) < message_length:
                    part = client_socket.recv(message_length - len(data))
                    if not part:
                        break
                    data = data + part

                if len(data) != message_length:
                    break

                address = self.clients.get(client_socket, "Unknown")
                self.log(
                    "Received message from "
                    + str(address)
                    + " - relaying..."
                )
                self.relay_message(client_socket, data)
        except Exception as error:
            if self.running:
                self.log("Error handling client: " + str(error))
        finally:
            self.remove_client(client_socket)


    # إرسال الرسالة المشفرة إلى كل العملاء ما عدا المرسل
    def relay_message(self, sender_socket, data):
        message_length = len(data).to_bytes(4, byteorder="big")

        for client_socket in list(self.clients):
            if client_socket != sender_socket:
                try:
                    client_socket.sendall(message_length + data)
                except Exception:
                    self.remove_client(client_socket)


    # إزالة عميل وإغلاق socket الخاص به
    def remove_client(self, client_socket):
        if client_socket in self.clients:
            address = self.clients[client_socket]
            del self.clients[client_socket]

            try:
                client_socket.close()
            except Exception as error:
                print("Error closing disconnected client:", error)

            self.log("Client " + str(address) + " disconnected")


    # تشغيل حلقة واجهة Tkinter
    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    server = ChatServer()
    server.run()
