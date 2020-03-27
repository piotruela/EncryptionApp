import sys
import os

from PyQt5.QtWidgets import \
    QApplication, QMainWindow, QPushButton, QLineEdit, QFileDialog, \
    QProgressBar
from EncryptionApp.communicator import Communicator


class Window(QMainWindow):
    def __init__(self, communicator: Communicator):
        super(Window, self).__init__()
        self.setGeometry(300, 300, 600, 400)
        self.setWindowTitle("Encryption application")
        self.communicator = communicator
        self.message_box = None
        self.filename_box = None
        self.sending_progress = None
        self.receiving_progress = None
        self.home()
        self.show()

    def home(self) -> None:
        self.message_box = QLineEdit(self)
        self.message_box.resize(150, 20)
        self.message_box.move(80, 50)
        message_button = QPushButton("Send message", self)
        message_button.resize(message_button.minimumSizeHint())
        message_button.move(85, 80)
        message_button.clicked.connect(self.send_message)

        self.filename_box = QLineEdit(self)
        self.filename_box.resize(150, 20)
        self.filename_box.move(280, 50)
        choose_file_button = QPushButton("Choose file", self)
        choose_file_button.resize(choose_file_button.minimumSizeHint())
        choose_file_button.move(285, 80)
        choose_file_button.clicked.connect(self.choose_file)
        file_button = QPushButton("Send file", self)
        file_button.resize(file_button.minimumSizeHint())
        file_button.move(285, 110)
        file_button.clicked.connect(self.send_file)
        self.sending_progress = QProgressBar(self)
        self.sending_progress.resize(200, 30)
        self.sending_progress.move(285, 130)

    def send_message(self) -> None:
        self.communicator.send_text(self.message_box.text())
        self.message_box.clear()

    def send_file(self) -> None:
        self.sending_progress.setValue(0)
        self.communicator.send_file(self.filename_box.text(), self.sending_progress)
        self.filename_box.clear()

    def choose_file(self) -> None:
        filename = QFileDialog.getOpenFileName(self, "Open file", "./")
        path, filename = os.path.split(filename[0])
        self.filename_box.setText(filename)

    @staticmethod
    def run(communicator) -> None:
        app = QApplication(sys.argv)
        gui = Window(communicator)
        sys.exit(app.exec_())
