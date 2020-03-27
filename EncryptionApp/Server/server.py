import socket
import logging
import threading

from EncryptionApp.communicator import Communicator
from EncryptionApp.GUI import Window

logging.basicConfig(level=logging.INFO)


def receiving(communicator: Communicator):
    while True:
        communicator.receive()


def print_menu() -> str:
    print("1 - send message")
    print("2 - send file")
    print("q - quit")
    return input("\n")


def main():
    server = socket.socket()
    server.bind(('localhost', 9999))
    server.listen(1)
    conn, addr = server.accept()

    communicator = Communicator(conn=conn)

    communicator.send_session_key()
    communicator.receive()

    receiving_thread = threading.Thread(target=receiving, args=(communicator, ))
    receiving_thread.start()

    Window.run(communicator)

    conn.close()
    server.close()


if __name__ == '__main__':
    main()
