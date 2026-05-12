"""
Secure Password Manager
Entry point of the application.
"""

from src.ui.cli import CLI


def main():
    app = CLI()
    app.run()


if __name__ == "__main__":
    main()