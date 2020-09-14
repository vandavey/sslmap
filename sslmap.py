import logging
import argparse
import shutil
import subprocess
from pathlib import Path
from xmltodict3 import XmlTextToDict
from datetime import datetime

# TODO: Split CIDR blocks larger than a.b.c.d/24 prior to scan


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
        """Convert Unix epoch timestamp to datetime string"""
        global date_fmt
        return datetime.fromtimestamp(int(stamp)).strftime(date_fmt)

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


def log_error(error_msg: str, terminate: bool) -> None:
    """Append error to log file and exit (optional)"""
    global logger
    print(f"[x] {error_msg} (see errors.log for full details)")
    logger.error(error_msg)
    if terminate:
        exit(1)


def log_argument(arg_name: str, msg: str) -> None:
    """Log errors caused by invalid cmd-line arguments"""
    global parser
    print(f"usage: {parser.usage}")
    log_error(f"ARGUMENT <{arg_name}>, '{msg}'", terminate=True)


def log_ex(exc, close: bool = True) -> None:
    """Log errors caused by unhandled exceptions"""
    if Exception in type(exc).mro():
        msg = f"EXCEPTION <{type(exc).__name__}>, '{exc.args[0]}'"
    else:
        msg = f"EXCEPTION <{exc[0]}>, '{exc[1]}'"
    log_error(msg, terminate=close)


def run_scan(nm_args: list) -> str:
    """Execute Nmap scan and return the process output"""
    nm_stats = None
    try:
        nm_stats = subprocess.run(
            args=nm_args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8"
        )
    except Exception as nm_ex:
        log_ex(nm_ex, close=True)

    # Don't exit on error (replicate Nmap behavior)
    if nm_stats.stderr != "":
        for error in nm_stats.stderr.splitlines():
            nm_error = error[:-1].split(": ")  # Split label and msg
            if nm_error[0] == "WARNING":
                print(f"[!] NMAP: {nm_error[1]}")
            else:
                log_ex(("NmapScan", nm_error[0]), close=False)

    return nm_stats.stdout.replace("\r", "").replace("\n", "")


def parse_xml(xml: str) -> list:
    """Parse each host XML string out of raw XML data"""
    host_list = []
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

        # Skip if no NSE scan data's available
        if "script" in item.keys():
            for script in item["script"]:
                lines = script["@output"].replace(",", "").splitlines()

                if script["@id"] == "ssl-cert":
                    names = lines[1].split()
                    names = [n for n in names if ("DNS" in n)]

                    for name in names:
                        url = name.split(":")[1]

                        if url != host_info.IPAddress:
                            host_info.URL = url
                            break
                elif script["@id"] == "ssl-enum-ciphers":
                    strength = lines[-1][-1]  # Last char of last line

        host_info.PortList.append((item["@portid"], strength))
    return host_info


# Initialize cmd-line arguments parser and arguments
parser = argparse.ArgumentParser(
    prog="sslmap.py",
    usage="sslmap.py [-h] [-o OUTPUT] [-p PORT] TARGET",
    description="SSL cipher strength grader (python3)"
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

# Resolve relative CSV path if applicable
if csv_path is not None:
    if (csv_path.anchor == "") & (csv_path.name != "-"):
        csv_path = (Path.cwd() / csv_path).resolve()
    else:
        csv_path = csv_path.resolve()

# Place error log with CSV file
if (csv_path is not None) & (csv_path.parent.exists()):
    log_path = (csv_path.parent / "errors.log").resolve()
else:
    log_path = Path.cwd() / "errors.log"

# Default CSV file header
header = "|".join((
    '"IPAddress"', '"Port"', '"HostName"', '"URL"',
    '"Strength"', '"StartTime"', '"EndTime"'
))

# Nmap (TCP connect) scan parameters
nm_params = (
    "-sT", "-Pn", "-oX", "-", "-p", ports,
    "--script", "ssl-cert,ssl-enum-ciphers"
)

# Datetime string format
date_fmt = "%m/%d/%Y %I:%M:%S %p"

# Initialize error logger
logger = logging.getLogger("errors")
logger.setLevel(logging.ERROR)
handler = logging.FileHandler(log_path, "a")

# Customize logger formatting
handler.setFormatter(logging.Formatter(
    fmt="[%(asctime)s] %(levelname)s: %(message)s",
    datefmt=date_fmt
))

logger.addHandler(handler)

# Primary entry point
if __name__ == "__main__":
    if len(target) == 0:
        log_argument("TARGET", "At least one value is required")

    if ports is None:
        log_argument("PORT", "An argument value is required")

    # Validate port(s) parsed from cmd-line
    for port in ports.split(","):
        if not port.isdigit():
            log_argument("PORT", f"{port} is not an integer")
        elif not (0 <= int(port) <= 65535):
            log_argument("PORT", f"Invalid port number {port}")

    # Validate CSV output path
    if csv_path is None:
        log_argument("OUTPUT", "An argument value is required")
    elif not csv_path.parent.exists():
        log_argument("OUTPUT", f"Invalid parent path {csv_path.parent}")

    # Locate Nmap executable file
    exec_path = shutil.which("nmap")
    if exec_path is None:
        log_ex(("NmapPath", "Unable to locate Nmap executable"))

    # Skip if CSV output target is console stdout
    if csv_path.name != "-":
        csv_path.touch()
        csv_lines = csv_path.read_text().splitlines()

        # Add CSV field header to file if missing
        if len(csv_lines) == 0:
            csv_path.write_text(header + "\n")
        elif csv_lines[0] != header:
            csv_path.write_text("\n".join([header, *csv_lines, ""]))

    print("[*] Beginning scan, this could take a while...")
    raw_xml = run_scan([exec_path, *nm_params, *target])

    host_strings = parse_xml(raw_xml)
    host_count = len(host_strings)

    # Format and print CSV field names
    if (host_count != 0) & (csv_path.name == "-"):
        heading = header.replace('"', "")
        heading = f"\n{heading}\n" + ("-" * len(heading))
        print(heading)

    # For each XML string, parse host data and append to CSV
    for host_xml in host_strings:
        info_dict = XmlTextToDict(host_xml).get_dict()["host"]
        new_line = get_info(info_dict).to_csv()

        if csv_path.name != "-":
            with csv_path.open("a") as csv:
                csv.write(new_line + "\n")
        else:
            print(new_line.replace('"', ""))

    exit_msg = ["[*] SSL scan completed"]

    if host_count == 0:
        exit_msg.append(f"    ERRORS => '{log_path}'")
    elif (csv_path.name != "-") & (host_count > 0):
        exit_msg.append(f"    OUTPUT => '{csv_path}'")
    else:
        exit_msg = ["", *exit_msg]

    print(*exit_msg, sep="\n")
