import socket
import logging
import threading

from EncryptionApp.communicator import Communicator

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

    while True:
        choice = print_menu()
        if choice == 'q':
            break
        elif choice == '1':
            message = input("Type message to send: ")
            communicator.send_text(message)
        elif choice == '2':
            filename = input("Type file name to send: ")
            communicator.send_file(filename)

    conn.close()
    server.close()


if __name__ == '__main__':
    main()
