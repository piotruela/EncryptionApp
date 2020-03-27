import logging

from EncryptionApp.GUI import App

logging.basicConfig(level=logging.INFO)


def main():
    App.run(as_server=True)


if __name__ == '__main__':
    main()
