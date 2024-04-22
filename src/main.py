import sys
from PyQt5.QtWidgets import QApplication


def main():
    from app.capture.main_window import MainWindow

    app = QApplication(sys.argv)

    main_app = MainWindow()
    main_app.showMaximized()

    return app.exec_()


if __name__ == "__main__":
    sys.exit(main())
