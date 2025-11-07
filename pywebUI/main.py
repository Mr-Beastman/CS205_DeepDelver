import webview
from pathlib import Path
from .controller.controller import GUIController

def main():
    controller = GUIController()
    htmlPath = Path(__file__).parent / "templates" / "index.html"

    webview.create_window(
        title="DeepDelver",
        url=htmlPath.as_uri(),
        width=900,
        height=700,
        js_api=controller,
    )

    webview.start()

if __name__ == "__main__":
    main()
