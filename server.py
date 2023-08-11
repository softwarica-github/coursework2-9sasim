import socket
import threading
import sys
import rsa
import sqlite3
import hashlib

HOST = "127.0.0.1"
PORT = 9999

PUBLIC_KEY_SIZE = 2048

class ChatServer:
    def __init__(self):
        self.clients = {}
        self.lock = threading.Lock()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((HOST, PORT))
        print(f"Server is starting......\n[LISTENING] on {HOST}:{PORT}")

        self.public_key, self.private_key = rsa.newkeys(PUBLIC_KEY_SIZE)
        self.usernames = []
    def broadcast(self, message, sender_name=None):
        with self.lock:

            for client_name, client_data in self.clients.items():
                if sender_name != client_name:
                    print(message)
                    encrypted_message = rsa.encrypt(message.encode('utf-8'), client_data['public_key'])
                    client_data['socket'].send(encrypted_message)


    def handle_client(self, client_socket, client_address):
        try:

            public_key = rsa.PublicKey.load_pkcs1(client_socket.recv(1024))

            username = rsa.decrypt(client_socket.recv(1024), self.private_key).decode('utf-8')
            print(username)

            password = rsa.decrypt(client_socket.recv(1024), self.private_key).decode('utf-8')
            print(password)

            password = hashlib.sha256(password.encode()).hexdigest()
            conn = sqlite3.connect('userdata.db')
            cur = conn.cursor()
            cur.execute('SELECT * FROM userdata WHERE username = ? AND password = ?',(username , password))

            if cur.fetchone():
                print(f"\n{username} [JOINED] chat community :)")

                login = rsa.encrypt("LOGIN".encode('utf-8'), public_key)
                client_socket.send(login)

                self.clients[username] = client_socket
            else:
                failed = rsa.encrypt("FAILED".encode('utf-8'), public_key)
                client_socket.send(failed)


            self.clients[username] = {'socket': client_socket, 'public_key': public_key}
            self.broadcast(f"\n{username} joined the chat\n", username)


            while True:

                encrypted_message = client_socket.recv(1024)

                if not encrypted_message:
                    break

                decrypted_message = rsa.decrypt(encrypted_message, self.private_key).decode('utf-8')
                print(decrypted_message)


                def search_user(clients, username_op):
                    if username_op in self.clients:
                        return clients[username_op]
                    else:
                        return "NotFound"
                if decrypted_message.lower() == "quit":
                    self.broadcast(f"{username} LEFT THE CHAT!", username)
                    client_socket.close()
                    with self.lock:
                        del self.clients[username]
                    break
                elif '@' in decrypted_message:
                    b = decrypted_message.split("|")
                    if len(b) == 2:
                        print(b[0])
                        print(b[1])
                        c = b[0].split('@')
                        print(c[0])
                        print(c[1])
                        calculate_hash = hashlib.sha256(b[0].encode('utf-8')).hexdigest()
                        if calculate_hash == b[1]:
                            print(c[0])
                            msg_hash = hashlib.sha256(c[1].encode("utf-8")).hexdigest()
                            print(msg_hash)
                            combined = f"{c[0]}|{c[1]}|{msg_hash}"
                            print("combine:",combined)
                            recipient_socket = search_user(self.clients,c[0])
                            if recipient_socket:
                                print("iam here")
                                sending_pri = rsa.encrypt(combined.encode("utf-8"), recipient_socket["public_key"])
                                recipient_socket["socket"].send(sending_pri)

                            else:
                                print("Cannot send")
                        else:
                            print("Message has benn corrupt")

                    else:
                        print("Not found hehe")
                else:
                    self.broadcast(f"{username}|{decrypted_message}", username)

        except Exception as e:
            print(f"[EXCEPTION] due to {e}")

    def start_server(self):
        try:
            self.server.listen()

            while True:
                client_socket, client_address = self.server.accept()
                print(f"[NEW CONNECTION] from {client_address}!")
                client_socket.send(self.public_key.save_pkcs1("PEM"))
                threading.Thread(target=self.handle_client, args=(client_socket, client_address)).start()

        except KeyboardInterrupt:
            print("Server is terminating...")
            with self.lock:
                for client_data in self.clients.values():
                    client_data['socket'].close()
            self.server.close()

if __name__ == '__main__':
    chat_server = ChatServer()
    chat_server.start_server()
