"""Entry point for filesnitch-ui."""

from filesnitch_ui.app import FilesnitchApp


def main():
    app = FilesnitchApp()
    app.run()


if __name__ == "__main__":
    main()
