import socket
import logging
import threading

from EncryptionApp.communicator import Communicator
from EncryptionApp.GUI import Window

logging.basicConfig(level=logging.INFO)


def receiving(communicator: Communicator):
    while True:
        communicator.receive()


def main():
    client = socket.socket()
    client.connect(('localhost', 9999))

    communicator = Communicator(conn=client)

    communicator.receive()
    communicator.send_session_key()

    receiving_thread = threading.Thread(target=receiving, args=(communicator, ))
    receiving_thread.start()

    Window.run(communicator)

    client.close()


if __name__ == '__main__':
    main()
