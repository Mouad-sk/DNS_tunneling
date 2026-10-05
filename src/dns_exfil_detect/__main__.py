"""Allow ``python -m dns_exfil_detect``."""

from dns_exfil_detect.cli.main import app

if __name__ == "__main__":
    app()
