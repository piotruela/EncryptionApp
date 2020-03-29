import sys
import logging

sys.path.append("/Users/hubertskrzypczak/PycharmProjects/BSK_1/")

from EncryptionApp.GUI import App

logging.basicConfig(level=logging.DEBUG)


def main():
    App.run(as_server=True)


if __name__ == '__main__':
    main()
