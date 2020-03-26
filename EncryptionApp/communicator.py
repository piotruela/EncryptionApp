import os
import socket
import logging
from enum import Enum

from Crypto.Cipher import AES

BYTE_ORDER = 'little'


class MessageType(Enum):
    SESSION_KEY = int(1).to_bytes(4, BYTE_ORDER),
    FILE = int(2).to_bytes(4, BYTE_ORDER),
    TEXT = int(3).to_bytes(4, BYTE_ORDER),


class Communicator:
    def __init__(self, conn, buffer_size=1024):
        self.conn = conn
        self.buffer_size = buffer_size
        self.session_key = os.urandom(32)
        self.foreign_session_key = None

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

        bytes_received = 0
        while file_size - bytes_received > 0:
            if file_size - bytes_received < self.buffer_size:
                file.write(self.conn.recv(file_size - bytes_received))
                break
            buffer = self.conn.recv(self.buffer_size)
            bytes_received += self.buffer_size
            file.write(buffer)

        file.close()
        logging.info(f"Received file: {file_name}")

    def receive_text(self, length: bytes) -> None:
        nonce = self.conn.recv(int.from_bytes(length, BYTE_ORDER))
        text_len = self.conn.recv(4)
        text_len = int.from_bytes(text_len, BYTE_ORDER)
        encrypted_text = self.conn.recv(text_len)

        cipher = AES.new(self.foreign_session_key, AES.MODE_EAX, nonce=nonce)

        decrypted_text = cipher.decrypt(encrypted_text)

        logging.debug(f"Encrypted text: {encrypted_text}")
        logging.debug(f"Cipher nonce: {nonce}")
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

    def send_file(self, file_name: str) -> None:
        self.send(MessageType.FILE.value[0])
        file_name_in_bytes = bytes(file_name, 'utf-8')
        self.send(len(file_name_in_bytes).to_bytes(4, BYTE_ORDER))
        self.send(file_name_in_bytes)
        file = open(file_name, 'rb')
        file_size = os.path.getsize(file_name)
        self.send(file_size.to_bytes(4, BYTE_ORDER))

        bytes_sent = 0
        while file_size - bytes_sent > 0:
            buffer = file.read(self.buffer_size)
            self.send(buffer)
            bytes_sent += self.buffer_size
        logging.info(f"Sent file: {file_name}")
        file.close()

    def send_text(self, text: str) -> None:
        self.send(MessageType.TEXT.value[0])
        text_in_bytes = bytes(text, 'utf-8')

        cipher = AES.new(self.session_key, AES.MODE_EAX)

        encrypted_text = cipher.encrypt(text_in_bytes)
        nonce = cipher.nonce

        self.send(len(nonce).to_bytes(4, BYTE_ORDER))
        self.send(nonce)

        self.send(len(encrypted_text).to_bytes(4, BYTE_ORDER))
        self.send(encrypted_text)

        logging.debug(f"Encrypted text: {encrypted_text}")
        logging.debug(f"Cipher nonce: {nonce}")
        logging.info(f"Sent text: {text}")
