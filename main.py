"""STIG Group Assessment Tool - start here.

    python main.py

Launches the GUI. All logic lives in src/. Needs only the Python standard library (3.8+).
"""
import logging
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))


def show_error(title, message):
    try:
        import tkinter
        from tkinter import messagebox
        root = tkinter.Tk()
        root.withdraw()
        messagebox.showerror(title, message)
        root.destroy()
    except Exception:
        print(f"{title}: {message}", file=sys.stderr)


def main():
    try:
        import store
        store.ensure_folders()
        logging.basicConfig(filename=store.paths.logs / "stigtool.log", level=logging.INFO,
                            format="%(asctime)s %(levelname)s %(message)s")
    except Exception as e:
        show_error("Startup failed", f"Could not create the project folders next to main.py:\n{e}")
        return 1
    try:
        import gui
        app = gui.App()

        def on_error(exc, value, tb):
            logging.error("Unhandled error:\n%s", "".join(traceback.format_exception(exc, value, tb)))
            from tkinter import messagebox
            messagebox.showerror("Error", f"{value}\n\nDetails were written to logs/stigtool.log")

        app.report_callback_exception = on_error
        logging.info("Started by %s", store.current_user())
        app.mainloop()
    except Exception as e:
        logging.exception("Startup failed")
        show_error("Startup failed", f"{e}\n\nDetails were written to logs/stigtool.log")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
