from PyQt5.QtCore import QThread, pyqtSignal


class ReceiverThread(QThread):
    data_received_signal = pyqtSignal(object)

    def __init__(self, communicator):
        QThread.__init__(self)
        self.communicator = communicator
        self.communicator.data_received_signal = self.data_received_signal

    def run(self) -> None:
        while True:
            self.communicator.listen()
