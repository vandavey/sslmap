import logging
import argparse
from pathlib import Path
from xmltodict3 import XmlTextToDict
from datetime import datetime
from nmap3 import Nmap

# TODO: Run Nmap process manually so stderr can be redirected
# TODO: Possibly change logic to scan host individually


class HostInfo(object):
    """Class to store scan data specific to each target host"""
    def __init__(self, name_info, ip_info, time_stamps):
        if type(name_info) is list:
            self.HostName = name_info[0]["@name"]
        else:
            self.HostName = name_info["@name"]

        ip_items = ip_info if (type(ip_info) is list) else [ip_info]
        for item in ip_items:
            if item["@addrtype"] == "ipv4":
                self.IPAddress = item["@addr"]
                break

        self.StartTime = self.to_datetime(time_stamps[0])
        self.EndTime = self.to_datetime(time_stamps[1])
        self.URL = None
        self.PortList = []

    @staticmethod
    def to_datetime(stamp: str) -> str:
        """Convert Unix epoch timestamp into datetime string"""
        global date_fmt
        try:
            return datetime.fromtimestamp(int(stamp)).strftime(date_fmt)
        except Exception as stamp_ex:
            log_ex(stamp_ex)

    def to_csv(self) -> str:
        """Format and return host info as CSV record entries"""
        records = []
        for port_num, strength in self.PortList:
            records.append("|".join([
                f'"{self.IPAddress}"',
                f'"{port_num}"',
                f'"{self.HostName}"',
                f'"{self.URL}"',
                f'"{strength}"',
                f'"{self.StartTime}"',
                f'"{self.EndTime}"'
            ]))
        return "\n".join(records).replace("None", "")


def log_error(msg: str) -> None:
    """Append specified error string or exception to log file"""
    global log_path, logger, parser
    print(f"[x] {msg} (see {log_path.name} for full details)")
    logger.error(msg)
    exit(1)


def log_arg(arg_name: str, msg: str) -> None:
    """Log errors caused by invalid cmd-line arguments"""
    print(f"usage: {parser.usage}")
    log_error(f'ARGUMENT <{arg_name}>, "{msg}"')


def log_ex(exc: Exception) -> None:
    """Log errors caused by unhandled exceptions"""
    log_error(f'EXCEPTION <{type(exc).__name__}>, "{exc.args}"')


def parse_xml(xml: str) -> list:
    """Parse each host XML string out of raw XML data"""
    host_list = []
    xml = xml.replace("\r", "").replace("\n", "")

    # Tag count determines iteration count
    for i in range(xml.count("</host>")):
        start = xml.find("<host")
        end = xml.find("</host>") + len("</host>")

        host_list.append((xml[start:end]))  # Add host XML substring
        xml = xml[:start] + xml[end:]  # Remove substring from raw XML

    return host_list


def get_info(host_dict: dict) -> HostInfo:
    """Extract information from host XML dictionaries"""
    host_info = HostInfo(
        host_dict["hostnames"]["hostname"],
        host_dict["address"],
        (
            host_dict["@starttime"], host_dict["@endtime"]
        )
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
    prog="sslmap.py",
    description="python 3 SSL strength grader",
    usage="sslmap.py [-h] [-o OUTPUT] [-p PORT] TARGET"
)

parser.add_argument(
    "TARGET", type=str, nargs="*",
    help="specify the nmap scan target(s)"
)

parser.add_argument(
    "-o", "--output", type=str, nargs="?",
    help="specify file path for CSV output data",
    default=(Path.cwd() / "scan.csv")
)

parser.add_argument(
    "-p", "--port", type=str, nargs="?",
    help="specify the scan target port(s)",
    default="443,8443"
)

# Parse cmd-line arguments
args = parser.parse_args()

# Initialize global variables
target = list(args.TARGET)
csv_path = None if (args.output is None) else Path(args.output)
ports = None if (args.port is None) else str(args.port)

log_path = Path.cwd() / "errors.log"
date_fmt = "%m/%d/%Y %I:%M:%S %p"

# Default CSV file header
header = "|".join((
    '"IPAddress"', '"Port"', '"HostName"', '"URL"',
    '"Strength"', '"StartTime"', '"EndTime"'
))

# Nmap scan parameters
scan_args = [
    "-sT", "-Pn",  # TCP connect (skip discovery)
    "-oX", "-",  # Output results as XML
    "-p", ports,  # Target port(s)
    "--script", "ssl-cert,ssl-enum-ciphers"
]

# Initialize error logger
logger = logging.getLogger("errors")
logger.setLevel(logging.ERROR)
handler = logging.FileHandler("errors.log", "a")

# Customize logger formatting
handler.setFormatter(logging.Formatter(
    fmt="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt=date_fmt
))

logger.addHandler(handler)

# Primary entry point
if __name__ == "__main__":
    if len(target) == 0:
        log_arg("TARGET", "At least one value is required")

    if ports is None:
        log_arg("PORT", "An argument value is required")

    # Validate port(s) parsed from cmd-line
    for port in ports.split(","):
        if not port.isdigit():
            log_arg("PORT", f"{port} is not an integer")
        elif not (0 <= int(port) <= 65535):
            log_arg("PORT", f"Invalid port number {port}")

    # Validate CSV output path
    if csv_path is None:
        log_arg("OUTPUT", "An argument value is required")
    elif not csv_path.parent.exists():
        log_arg("OUTPUT", f"Invalid parent path {csv_path.parent}")

    if str(csv_path) != "-":
        csv_path.touch()
        csv_lines = csv_path.read_text().split("\n")

        # Add CSV field header to file if missing
        if len(csv_lines) == 0:
            csv_path.write_text(header + "\n")
        elif csv_lines[0] != header:
            csv_path.write_text("\n".join([header, *csv_lines]))

    print("[*] Beginning scan, this could take a while...")
    command = f"nmap {' '.join(scan_args)} {' '.join(target)}"

    raw_xml = ""
    try:
        raw_xml = Nmap().run_command(command)
    except Exception as nm_ex:
        log_ex(nm_ex)

    raw_xml = raw_xml.replace("\r", "").replace("\n", "")
    host_strings = parse_xml(raw_xml)

    if str(csv_path) == "-":
        print(header)

    # For each XML string, parse host data and append to CSV
    for host_xml in host_strings:
        info_dict = XmlTextToDict(host_xml).get_dict()["host"]
        new_line = get_info(info_dict).to_csv()

        if str(csv_path) != "-":
            with csv_path.open("a") as csv:
                csv.write(new_line + "\n")
        else:
            print(new_line)

    print("[*] SSL scan completed successfully")
