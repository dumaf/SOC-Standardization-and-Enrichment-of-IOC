"""Launch the TAXII 2.1 server.

Usage::

    python run_taxii_server.py

The server binds to the host/port specified in ``taxii_server/config.py``
(default **localhost:6100**) and can be overridden with environment
variables ``TAXII_HOST`` and ``TAXII_PORT``.
"""

import logging
import sys

from taxii_server.app import create_app
from taxii_server.seed import seed_database
from taxii_server import config

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("taxii_server")


def main():
    app = create_app()

    with app.app_context():
        seed_database()

    log.info(
        "Starting TAXII 2.1 server at http://%s:%d",
        config.HOST,
        config.PORT,
    )
    log.info("Discovery:   http://%s:%d/taxii2/", config.HOST, config.PORT)
    log.info("Health:      http://%s:%d/health", config.HOST, config.PORT)
    log.info("Collections: http://%s:%d/api/collections/", config.HOST, config.PORT)

    try:
        app.run(host=config.HOST, port=config.PORT, debug=False)
    except KeyboardInterrupt:
        log.info("Server stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
