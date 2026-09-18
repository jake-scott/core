"""Emulated Hue quick start."""
import argparse
import asyncio
import json
import logging
import os
import traceback

from aiorun import run
from hass_client.exceptions import CannotConnect

from emulated_hue import HueEmulator, const

IS_SUPERVISOR = os.path.isfile("/data/options.json") and os.environ.get("HASSIO_TOKEN")


def _addon_option(key: str) -> str | None:
    """Read a single option from the Supervisor add-on options file.

    Options are normally exported as environment variables by the add-on's
    init scripts, but this fallback lets newly added options work even when
    running on an older container image whose init scripts don't know them.
    """
    if not IS_SUPERVISOR:
        return None
    try:
        with open("/data/options.json", encoding="utf-8") as fp:
            value = json.load(fp).get(key)
    except (OSError, ValueError):
        return None
    return str(value).strip() if value not in (None, "") else None

# pylint: disable=invalid-name
if __name__ == "__main__":
    logger = logging.getLogger()
    logformat = logging.Formatter(
        "%(asctime)-15s %(levelname)-5s %(name)s -- %(message)s"
    )
    consolehandler = logging.StreamHandler()
    consolehandler.setFormatter(logformat)
    logger.addHandler(consolehandler)
    logger.setLevel(logging.INFO)

    if IS_SUPERVISOR:
        default_data_dir = "/config/hass-emulated-hue"
    else:
        default_data_dir = (
            os.getenv("APPDATA") if os.name == "nt" else os.path.expanduser("~")
        )
        default_data_dir = os.path.join(default_data_dir, ".emulated_hue")

    parser = argparse.ArgumentParser(description="Home Assistant HUE Emulation.")

    parser.add_argument(
        "--data",
        type=str,
        help="path to store config files",
        default=os.getenv("DATA_DIR", default_data_dir),
    )
    parser.add_argument(
        "--url",
        type=str,
        help="url to HomeAssistant",
        default=os.getenv("HASS_URL", "http://hassio/homeassistant"),
    )
    parser.add_argument(
        "--token",
        type=str,
        help="Long Lived Token for HomeAssistant",
        default=os.getenv("HASS_TOKEN", os.getenv("HASSIO_TOKEN")),
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable more verbose logging"
    )
    parser.add_argument(
        "--http-port",
        type=int,
        help="Port to run the HTTP server (for use with reverse proxy, use with care)",
        default=os.getenv("HTTP_PORT", const.HUE_HTTP_PORT),
    )
    parser.add_argument(
        "--https-port",
        type=int,
        help="Port to run the HTTPS server (for use with reverse proxy, use with care)",
        default=os.getenv("HTTPS_PORT", const.HUE_HTTPS_PORT),
    )
    parser.add_argument(
        "--listen-ip",
        type=str,
        help="IPv4 address to bind the HTTP/HTTPS servers to and to advertise "
        "during discovery. Defaults to auto-detection (the interface with the "
        "default route). Use this on multi-homed hosts (VLANs, VPNs, docker bridges).",
        default=os.getenv("LISTEN_IP") or _addon_option("listen_ip"),
    )
    parser.add_argument(
        "--use-default-ports-for-discovery",
        action="store_true",
        help=f"Always use HTTP port {const.HUE_HTTP_PORT} and HTTPS port {const.HUE_HTTPS_PORT} for discovery "
        f"regardless of actual exposed ports. Useful with reverse proxy.",
    )

    args = parser.parse_args()
    datapath = args.data
    url = args.url
    token = args.token
    if args.verbose or os.getenv("VERBOSE", "").strip() == "true":
        logger.setLevel(logging.DEBUG)
    use_default_ports = False
    if (
        args.use_default_ports_for_discovery
        or os.getenv("USE_DEFAULT_PORTS", "").strip() == "true"
    ):
        use_default_ports = True
    # turn down logging for hass-client
    logging.getLogger("hass_client").setLevel(logging.INFO)

    listen_ip = (args.listen_ip or "").strip() or None

    hue = HueEmulator(
        datapath,
        url,
        token,
        args.http_port,
        args.https_port,
        use_default_ports,
        listen_ip,
    )

    def on_shutdown(loop):
        """Call on loop shutdown."""
        loop.run_until_complete(hue.async_stop())

    def handler(loop, context):
        """Handle exceptions in the loop."""
        if "exception" in context and isinstance(context["exception"], CannotConnect):
            ex = context["exception"]
            traceback.print_exception(type(ex), ex, ex.__traceback__)
            logger.error("Cannot connect to Home Assistant! Exiting...")
            loop.stop()

    if os.name != "nt":
        import uvloop

        main_loop = uvloop.new_event_loop()
    else:
        main_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(main_loop)

    main_loop.set_exception_handler(handler)

    run(hue.async_start(), shutdown_callback=on_shutdown, loop=main_loop)
