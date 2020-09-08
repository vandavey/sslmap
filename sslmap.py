import logging
import argparse
from pathlib import Path
from xmltodict3 import XmlTextToDict
from datetime import datetime
from nmap3 import Nmap

# TODO: Add logic to dump CSV output to console (--out -)
# TODO: Customize argument parsing so errors are logged
# TODO: ?> Change logic to scan host individually


class HostInfo(object):
    """Class to store scan data specific to each target host"""
    def __init__(self, ip_info, time_stamps, name_info):
        self.IPAddress = self.get_addr(ip_info)
        self.StartTime, self.EndTime = self.get_times(time_stamps)
        self.Name = self.get_name(name_info)
        self.URL = None
        self.PortList = []

    @staticmethod
    def get_addr(info) -> str:
        """Get the IPv4 address given a dictionary or list"""
        items = info if (type(info) is list) else [info]
        for item in items:
            if item["@addrtype"] == "ipv4":
                return item["@addr"]

    @staticmethod
    def get_times(stamps: tuple) -> tuple:
        """Convert Unix epoch times to date-time strings"""
        global date_fmt
        return (
            datetime.fromtimestamp(int(stamps[0])).strftime(date_fmt),
            datetime.fromtimestamp(int(stamps[1])).strftime(date_fmt)
        )

    @staticmethod
    def get_name(info) -> str:
        """Get the host name given a dictionary or list"""
        if type(info) is list:
            return info[0]["@name"]
        else:
            return info["@name"]

    def to_csv(self) -> str:
        """Format and return host info as CSV record entries"""
        records = []
        for port_num, strength in self.PortList:
            records.append("|".join([
                f'"{self.IPAddress}"',
                f'"{port_num}"',
                f'"{self.Name}"',
                f'"{self.URL}"',
                f'"{strength}"',
                f'"{self.StartTime}"',
                f'"{self.EndTime}"'
            ]))
        return "\n".join(records).replace("None", "")


def log_error(error) -> None:
    """Append specified error string or exception to log file"""
    global logger, log_path, verbose
    if verbose:
        print(f"[x] {error} (see {log_path} for full details)")
    logger.error(error)
    exit(1)


def run_scan(addr: str) -> str:
    """Run the scan on the specified target. Return the
    XML scan output as a string to be parsed"""
    global scan_args, verbose
    if verbose:
        print("[*] Beginning scan, this could take a while...")

    try:
        return Nmap().run_command(f"nmap {' '.join(scan_args)} {addr}")
    except Exception as scan_ex:
        log_error(scan_ex)


def parse_xml(xml: str) -> list:
    """Parse each host XML string out of raw XML data"""
    host_list = []
    xml = xml.replace("\r", "").replace("\n", "")

    # Iteration count is determined by 'host' tag count
    for i in range(xml.count("</host>")):
        start = xml.find("<host")
        end = xml.find("</host>") + len("</host>")

        host_list.append((xml[start:end]))  # Add host XML substring
        xml = xml[:start] + xml[end:]  # Remove substring from raw XML

    return host_list


def get_info(host_dict: dict) -> HostInfo:
    """Extract information from host XML dictionaries"""
    host_info = HostInfo(
        host_dict["address"],
        (host_dict["@starttime"], host_dict["@endtime"]),
        host_dict["hostnames"]["hostname"]
    )

    pinfo = host_dict["ports"]["port"]
    port_list = pinfo if (type(pinfo) is list) else [pinfo]

    # Extract port and NSE script info
    for item in port_list:
        strength = None

        # Skip if no NSE scripts were used
        if "script" in item.keys():
            for script in item["script"]:
                lines = script["@output"].replace(",", "").split("\n")

                if script["@id"] == "ssl-cert":
                    names = lines[1].split()
                    names = [n for n in names if ("DNS" in n)]

                    for name in names:
                        url = name.split(":")[1]

                        if url != host_info.IPAddress:
                            host_info.URL = url
                            break
                elif script["@id"] == "ssl-enum-ciphers":
                    strength = lines[-1][-1]

        host_info.PortList.append((item["@portid"], strength))
    return host_info


# Initialize cmd-line arguments parser and arguments
parser = argparse.ArgumentParser(
    prog="sslmap",
    description="python 3 SSL strength grader",
    usage="sslmap.py [-h] [-v] [-o OUT] [-p PORT] TARGET"
)

parser.add_argument(
    "TARGET", type=str, nargs="+",  # At least one argument
    help="specify the nmap scan target(s)"
)

parser.add_argument(
    "-v", "--verbose", action="store_true",
    help="display console output for debugging"
)

parser.add_argument(
    "-o", "--out", type=str, default=(Path.cwd() / "scan.csv"),
    help="specify file path for CSV output data"
)

parser.add_argument(
    "-p", "--port", type=str, default="443,8443",
    help="specify the scan target port(s)"
)

# Parse cmd-line arguments
args = parser.parse_args()

# Initialize global variables
target = list(args.TARGET)
verbose = bool(args.verbose)
ports = str(args.port)
csv_path = Path(args.out)

log_path = Path.cwd() / "errors.log"
date_fmt = "%m/%d/%Y %I:%M:%S %p"

# Default CSV file header
header = "|".join((
    '"IPAddress"', '"Port"', '"HostName"', '"URL"',
    '"Strength"', '"StartTime"', '"EndTime"'
))

# Scan parameters to pass to Nmap
scan_args = [
    "-sT", "-Pn", "-oX", "-", "-p", ports,
    "--script", "ssl-cert,ssl-enum-ciphers"
]

# Initialize error logger to debug scheduled runs
logger = logging.getLogger("errors")
logger.setLevel(logging.ERROR)
handler = logging.FileHandler("errors.log", "a")

# Change the logger format style
handler.setFormatter(logging.Formatter(
    fmt="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt=date_fmt
))

logger.addHandler(handler)

# Program entry point
if __name__ == "__main__":
    # Validate port(s) parsed from cmd-line
    for port in ports.split(","):
        if not port.isdigit():
            log_error(f"{port} is not an integer")
        elif not (0 <= int(port) <= 65535):
            log_error(f"Invalid port number {port}")

    if not csv_path.parent.exists():
        log_error(f"Invalid parent path {csv_path.parent}")

    # Create the CSV file if not found
    csv_path.touch()
    csv_lines = csv_path.read_text().splitlines()

    # Add CSV field header to file if missing
    if len(csv_lines) == 0:
        csv_path.write_text(header + "\n")
    elif csv_lines[0] != header:
        csv_path.write_text("\n".join([header, *csv_lines]))

    raw_xml = ""
    try:
        raw_xml = run_scan(" ".join(target))
    except Exception as ex:
        log_error(ex)

    raw_xml = raw_xml.replace("\r", "").replace("\n", "")
    host_strings = parse_xml(raw_xml)

    # For each XML string, parse host data and append to CSV
    for host_xml in host_strings:
        info_dict = XmlTextToDict(host_xml).get_dict()["host"]

        with csv_path.open("a") as csv:
            new_line = get_info(info_dict).to_csv()
            csv.write(new_line + "\n")

    if verbose:
        print("[*] SSL scan completed successfully")
