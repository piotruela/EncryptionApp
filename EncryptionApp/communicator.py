import os
import socket
import logging
from enum import Enum

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PyQt5.QtWidgets import QApplication, QProgressBar
from PyQt5.QtCore import QThread, pyqtSignal

BYTE_ORDER = 'little'
KEY_SIZE = 32
AES.block_size = 16

logger = logging.getLogger(__name__)


class ReceiverThread(QThread):
    data_received_signal = pyqtSignal(object)

    def __init__(self, communicator):
        QThread.__init__(self)
        self.communicator = communicator
        self.communicator.data_received_signal = self.data_received_signal

    def run(self) -> None:
        while True:
            self.communicator.listen()


class MessageType(Enum):
    SESSION_KEY = int(1).to_bytes(4, BYTE_ORDER),
    FILE = int(2).to_bytes(4, BYTE_ORDER),
    TEXT = int(3).to_bytes(4, BYTE_ORDER),


class Communicator:
    def __init__(self, buffer_size=1024):
        if buffer_size % AES.block_size != 0:
            raise BaseException(f"buffer_size must be divisible by AES.block_size = {AES.block_size}")
        self.buffer_size = buffer_size
        self.session_key = os.urandom(KEY_SIZE)
        self.routing_table = {MessageType.SESSION_KEY.value[0]: self.receive_session_key,
                              MessageType.FILE.value[0]: self.receive_file,
                              MessageType.TEXT.value[0]: self.receive_text}
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
            self.send_session_key()
            self.listen()
            logger.info("Established connection as server")
        else:
            self.conn = socket.socket()
            self.conn.connect((ip, port))
            self.listen()
            self.send_session_key()
            logger.info("Established connection as client")

        self.receiver_thread = ReceiverThread(self)
        self.receiver_thread.start()

    def close_connection(self) -> None:
        if self.receiver_thread:
            self.receiver_thread.terminate()
            self.receiver_thread.wait()
            logger.info("Receiving thread has stopped")
        if self.conn:
            self.conn.close()
            logger.info("Closed connection")
        if self.server:
            self.server.close()
            logger.info("Closed server")

    def listen(self) -> None:
        message_type = self.receive_type()
        self.route(message_type)

    def route(self, message_type: bytes) -> None:
        try:
            self.routing_table[message_type]()
        except KeyError:
            logger.debug(f"No such key in routing_table. ({message_type})")
            exit(0)

    def receive_type(self) -> bytes:
        message_type = self.conn.recv(4)
        logger.debug(f"Received type: {int.from_bytes(message_type, BYTE_ORDER)}")
        return message_type

    def receive_length(self) -> int:
        message_length = int.from_bytes(self.conn.recv(4), BYTE_ORDER)
        logger.debug(f"Received length: {message_length}")
        return message_length

    def receive_session_key(self) -> None:
        key = self.receive_bytes()
        self.foreign_session_key = key
        logger.debug(f"Received session key: {key}")

    def receive_bytes(self) -> bytes:
        length = self.receive_length()
        data = self.conn.recv(length)
        return data

    def receive_file(self) -> None:
        file_name = self.receive_bytes()
        file_name = str(file_name, 'utf-8')
        file_size = self.receive_length()
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
        logger.info(f"Received file: {file_name}")

    def receive_text(self) -> None:
        mode = self.receive_mode()

        if mode == "ECB":
            cipher = AES.new(self.foreign_session_key, AES.MODE_ECB)
        elif mode == "CBC":
            iv = self.receive_bytes()
            cipher = AES.new(self.foreign_session_key, AES.MODE_CBC, iv=iv)
        elif mode == "CFB":
            iv = self.receive_bytes()
            cipher = AES.new(self.foreign_session_key, AES.MODE_CFB, iv=iv)
        elif mode == "OFB":
            iv = self.receive_bytes()
            cipher = AES.new(self.foreign_session_key, AES.MODE_OFB, iv=iv)
        else:
            raise BaseException("No such sending mode")

        encrypted_text = self.receive_bytes()
        decrypted_text = cipher.decrypt(encrypted_text)

        if mode in ["ECB", "CBC"]:
            decrypted_text = unpad(decrypted_text, AES.block_size)

        self.data_received_signal.emit(str(decrypted_text, 'utf-8'))

        logger.debug(f"Received encrypted text: {encrypted_text}")
        logger.debug(f"Receibed in mode: {mode}")
        logger.info(f"Received text: {str(decrypted_text, 'utf-8')}")

    def receive_mode(self) -> str:
        mode = self.receive_bytes()
        return str(mode, 'utf-8')

    def send(self, data: bytes) -> None:
        if self.conn:
            self.conn.send(data)
        else:
            logger.error("Couldn't sent data, because there is no client connection")

    def send_bytes(self, data: bytes) -> None:
        self.send(len(data).to_bytes(4, BYTE_ORDER))
        self.send(data)

    def send_session_key(self) -> None:
        self.send(MessageType.SESSION_KEY.value[0])
        self.send_bytes(self.session_key)
        logger.debug(f"Sent session key {self.session_key}")

    def send_file(self, file_path: str, progressbar: QProgressBar = None) -> None:
        self.send(MessageType.FILE.value[0])
        file_name = os.path.basename(file_path)
        file_name_in_bytes = bytes(file_name, 'utf-8')
        self.send_bytes(file_name_in_bytes)
        try:
            file = open(file_path, 'rb')
            file_size = os.path.getsize(file_path)
        except FileNotFoundError:
            file = None
            file_size = 0
            logger.debug(f"Sending empty file due to fact, becuase file {file_path} doesn't exist.")

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
                progress = min(int(bytes_sent / file_size * 100), 100)
                progressbar.setValue(progress)
                QApplication.processEvents()
                logger.debug(f"Sent {progress}% of file")
        progressbar.setValue(100)
        if file:
            file.close()
        logger.info(f"Sent file: {file_name}")

    def send_text(self, text: str, mode: str) -> None:
        self.send(MessageType.TEXT.value[0])
        text_in_bytes = bytes(text, 'utf-8')

        self.send_mode(mode)

        if mode == "ECB":
            cipher = AES.new(self.session_key, AES.MODE_ECB)
            encrypted_text = cipher.encrypt(pad(text_in_bytes, AES.block_size))
        elif mode == "CBC":
            cipher = AES.new(self.session_key, AES.MODE_CBC)
            encrypted_text = cipher.encrypt(pad(text_in_bytes, AES.block_size))
            self.send_bytes(cipher.iv)
        elif mode == "CFB":
            cipher = AES.new(self.session_key, AES.MODE_CFB)
            encrypted_text = cipher.encrypt(text_in_bytes)
            self.send_bytes(cipher.iv)
        elif mode == "OFB":
            cipher = AES.new(self.session_key, AES.MODE_OFB)
            encrypted_text = cipher.encrypt(text_in_bytes)
            self.send_bytes(cipher.iv)
        else:
            raise BaseException("No such sending mode")

        self.send_bytes(encrypted_text)

        logger.debug(f"Sent encrypted text: {encrypted_text}")
        logger.debug(f"Sent in mode: {mode}")
        logger.info(f"Sent text: {text}")

    def send_mode(self, mode: str) -> None:
        mode_in_bytes = bytes(mode, 'utf-8')
        self.send_bytes(mode_in_bytes)
