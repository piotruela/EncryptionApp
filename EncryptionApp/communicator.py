import os
import socket
import logging
from enum import Enum

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PyQt5.QtWidgets import QApplication, QProgressBar
from PyQt5.QtCore import QThread, pyqtSignal

BYTE_ORDER = 'little'


class ReceiverThread(QThread):

    data_received_signal = pyqtSignal(object)

    def __init__(self, communicator):
        QThread.__init__(self)
        self.communicator = communicator
        self.communicator.data_received_signal = self.data_received_signal

    def run(self) -> None:
        while True:
            self.communicator.receive()


class MessageType(Enum):
    SESSION_KEY = int(1).to_bytes(4, BYTE_ORDER),
    FILE = int(2).to_bytes(4, BYTE_ORDER),
    TEXT = int(3).to_bytes(4, BYTE_ORDER),


class Communicator:
    def __init__(self, buffer_size=1024):
        self.buffer_size = buffer_size
        self.session_key = os.urandom(32)
        self.conn = None
        self.server = None
        self.receiver_thread = None
        self.data_received_signal = None
        self.foreign_session_key = None

    def init_connection(self, ip: str, port: int, as_server: bool) -> None:
        if as_server:
            self.server = socket.socket()
            self.server.bind((ip, port))
            self.server.listen(1)
            self.conn, _ = self.server.accept()
            logging.info("Established connection as server")
            self.send_session_key()
            self.receive()
        else:
            self.conn = socket.socket()
            self.conn.connect((ip, port))
            logging.info("Established connection as client")
            self.receive()
            self.send_session_key()

        self.receiver_thread = ReceiverThread(self)
        self.receiver_thread.start()

    def close_connection(self) -> None:
        if self.receiver_thread:
            self.receiver_thread.terminate()
            self.receiver_thread.wait()
            logging.info("Receiving thread has stopped")
        if self.conn:
            self.conn.close()
            logging.info("Closed connection")
        if self.server:
            self.server.close()
            logging.info("Closed server")

    def receive(self) -> None:
        message_type = self.receive_type()
        message_length = self.receive_length()
        self.route(message_type, message_length)

    def receive_type(self) -> bytes:
        message_type = self.conn.recv(4)
        logging.debug(f"Received type: {int.from_bytes(message_type, BYTE_ORDER)}")
        return message_type

    def receive_length(self) -> bytes:
        message_length = self.conn.recv(4)
        logging.debug(f"Received length: {int.from_bytes(message_length, BYTE_ORDER)}")
        return message_length

    def receive_session_key(self, length: bytes) -> None:
        key = self.conn.recv(int.from_bytes(length, BYTE_ORDER))
        self.foreign_session_key = key
        logging.info(f"Received session key: {key}")

    def receive_file(self, length: bytes) -> None:
        file_name = self.conn.recv(int.from_bytes(length, BYTE_ORDER))
        file_name = str(file_name, 'utf-8')
        file_size = self.conn.recv(4)
        file_size = int.from_bytes(file_size, BYTE_ORDER)
        file = open(file_name, 'wb')

        cipher = AES.new(self.foreign_session_key, AES.MODE_ECB)

        bytes_received = 0
        while file_size - bytes_received > 0:
            if file_size - bytes_received < self.buffer_size:
                buffer = self.conn.recv(self.buffer_size)
                buffer = unpad(cipher.decrypt(buffer), AES.block_size)
                file.write(buffer)
                break
            buffer = self.conn.recv(self.buffer_size)
            buffer = cipher.decrypt(buffer)
            bytes_received += self.buffer_size
            file.write(buffer)
        file.close()

        self.data_received_signal.emit(f"Received file: {file_name}")
        logging.info(f"Received file: {file_name}")

    def receive_text(self, length: bytes) -> None:
        text_len = int.from_bytes(length, BYTE_ORDER)
        encrypted_text = self.conn.recv(text_len)

        cipher = AES.new(self.foreign_session_key, AES.MODE_ECB)

        decrypted_text = unpad(cipher.decrypt(encrypted_text), AES.block_size)
        self.data_received_signal.emit(str(decrypted_text, 'utf-8'))

        logging.debug(f"Encrypted text: {encrypted_text}")
        logging.info(f"Received text: {str(decrypted_text, 'utf-8')}")

    def route(self, message_type: bytes, message_length: bytes) -> None:
        if message_type == MessageType.SESSION_KEY.value[0]:
            self.receive_session_key(message_length)
        elif message_type == MessageType.FILE.value[0]:
            self.receive_file(message_length)
        elif message_type == MessageType.TEXT.value[0]:
            self.receive_text(message_length)

    def send(self, data: bytes) -> None:
        if self.conn:
            self.conn.send(data)
        else:
            logging.error("Couldn't sent data, because there is no client connection")

    def send_session_key(self) -> None:
        self.send(MessageType.SESSION_KEY.value[0])
        self.send(len(self.session_key).to_bytes(4, BYTE_ORDER))
        self.send(self.session_key)
        logging.info(f"Sent session key {self.session_key}")

    def send_file(self, file_path: str, progressbar: QProgressBar = None) -> None:
        self.send(MessageType.FILE.value[0])
        file_name = os.path.basename(file_path)
        file_name_in_bytes = bytes(file_name, 'utf-8')
        self.send(len(file_name_in_bytes).to_bytes(4, BYTE_ORDER))
        self.send(file_name_in_bytes)
        file = open(file_path, 'rb')
        file_size = os.path.getsize(file_path)
        self.send(file_size.to_bytes(4, BYTE_ORDER))

        cipher = AES.new(self.session_key, AES.MODE_ECB)

        bytes_sent = 0
        while file_size - bytes_sent > 0:
            buffer = file.read(self.buffer_size)
            if len(buffer) % AES.block_size != 0:
                buffer = pad(buffer, AES.block_size)
            self.send(cipher.encrypt(buffer))
            bytes_sent += self.buffer_size
            if progressbar:
                progress = min(int(bytes_sent/file_size * 100), 100)
                progressbar.setValue(progress)
                QApplication.processEvents()
                logging.debug(f"Sent {progress}% of file")
        logging.info(f"Sent file: {file_name}")
        file.close()

    def send_text(self, text: str) -> None:
        self.send(MessageType.TEXT.value[0])
        text_in_bytes = bytes(text, 'utf-8')

        cipher = AES.new(self.session_key, AES.MODE_ECB)
        encrypted_text = cipher.encrypt(pad(text_in_bytes, AES.block_size))

        self.send(len(encrypted_text).to_bytes(4, BYTE_ORDER))
        self.send(encrypted_text)

        logging.debug(f"Encrypted text: {encrypted_text}")
        logging.info(f"Sent text: {text}")
