from pathlib import Path
import socket
import sys

def blocked(*args, **kwargs):
    raise AssertionError("Offline verifier attempted a network connection")

socket.socket.connect = blocked
socket.socket.connect_ex = blocked
socket.create_connection = blocked
sys.path.insert(0, str(Path.cwd()))
from vote_lab.custody_cli import main
import vote_lab.custody_verify as verifier

assert Path(verifier.__file__).resolve().parent == Path.cwd() / "vote_lab"
code = main(sys.argv[1:])
assert "vote_lab.custody" not in sys.modules
assert "vote_lab.model" not in sys.modules
assert "vote_lab.server" not in sys.modules
raise SystemExit(code)
