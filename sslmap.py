import json
import logging
import argparse
import shutil
import subprocess
from pathlib import Path
from xmltodict3 import XmlTextToDict
from datetime import datetime

# TODO: Update README with new options/info
# TODO: Implement logic to update config and resume scan
# TODO: Finish config option implementation/debugging


class LogHandler(object):
    """Class to handle error logging operations"""
    def __init__(self, log_path: Path):  # Initializer
        handler = logging.FileHandler(log_path, "a")
        # Set msg/date formats of error logger
        handler.setFormatter(logging.Formatter(
            fmt="[%(asctime)s.%(msecs)d] %(message)s",
            datefmt=date_fmt
        ))
        # Initialize object properties
        self.FilePath = log_path
        self.Logger = logging.getLogger("errors")
        self.Logger.addHandler(handler)
        self.Logger.setLevel(logging.ERROR)

    def _handle(self, msg: str, kill: bool) -> None:
        """Protected helper method. Call self.error/self.option to
        append information to the log file instead of this method."""
        print(f"[x] {msg} (see errors.log for full details)")
        # Write error message to log file
        self.Logger.error(msg)
        if kill:  # Exit if <kill> is True
            exit(1)

    def option(self, arg_name: str, msg: str) -> None:
        """Log invalid cmd-line/config option and exit SSLMap"""
        global parser
        print(f"usage: {parser.usage}")
        self._handle(f"ARGUMENT ({arg_name}): {msg}", kill=True)

    def error(self, exc, close: bool = True) -> None:
        """Log general error to file and (optionally) exit SSLMap"""
        if Exception in type(exc).mro():  # if <exc> is real Exception
            msg = f"EXCEPTION ({type(exc).__name__}): {exc.args[0]}"
        else:
            msg = f"EXCEPTION ({exc[0]}): {exc[1]}"
        # Handle logging operation
        self._handle(msg, kill=close)

    def update_config(self) -> None:
        """Update config with scan statistics if it exists"""
        raise NotImplementedError("Feature in development")


class HostInfo(object):
    """Class to store scan data specific to each target host"""
    def __init__(self, name_info, ip_info, time_stamps):  # Initializer
        name_type = type(name_info)
        if name_type is list:
            self.HostName = name_info[0]["@name"]
        elif name_type is dict:
            self.HostName = name_info["@name"]
        else:
            self.HostName = None

        # Create list if <ip_info> is different type
        ip_items = ip_info if (type(ip_info) is list) else [ip_info]
        for item in ip_items:
            if item["@addrtype"] == "ipv4":
                self.IPAddress = item["@addr"]
                break

        self.StartTime = self.to_datetime(time_stamps[0])
        self.EndTime = self.to_datetime(time_stamps[1])
        self.DomainName = None
        self.PortList = []

    @staticmethod
    def to_datetime(stamp: str) -> str:
        """Convert Unix epoch timestamp to datetime string"""
        global date_fmt
        return datetime.fromtimestamp(int(stamp)).strftime(date_fmt)

    def to_csv(self) -> list:
        """Format and return host info as CSV record entries.
        Each additional port adds an item to the list returned."""
        records = []
        for port_num, strength in self.PortList:
            records.append("|".join((
                f'"{self.IPAddress}"',
                f'"{port_num}"',
                f'"{self.HostName}"',
                f'"{self.DomainName}"',
                f'"{strength}"',
                f'"{self.StartTime}"',
                f'"{self.EndTime}"'
            )))
        # Remove the 'None' keyword from each CSV record
        return [r.replace("None", "") for r in records]


def null(test_obj: object) -> bool:
    """Determine if the value of an object is null (None)"""
    return test_obj is None


def get_headers(names: tuple) -> dict:
    """Get CSV file header up/down hosts dictionary"""
    return {
        "up": "|".join(names),
        "down": "|".join((*names[:4], *names[5:]))
    }


def run_scan(nm_args: list) -> str:
    """Execute Nmap scan and return XML output data"""
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
        log.error(nm_ex, close=True)

    # Don't exit on error (replicate Nmap behavior)
    if nm_stats.stderr != "":
        for error in nm_stats.stderr.splitlines():
            nm_error = error[:-1].split(": ")  # Split label/msg
            if nm_error[0] == "WARNING":
                print(f"[!] NMAP: {nm_error[1]}")
            else:
                log.error(("NmapScan", nm_error[0]), close=False)
    # Remove line terminators before returning data
    return nm_stats.stdout.replace("\r", "").replace("\n", "")


def parse_xml(xml: str) -> list:
    """Parse each host XML string out of raw XML data"""
    host_list = []
    for i in range(xml.count("</host>")):
        start = xml.find("<host")
        end = xml.find("</host>") + len("</host>")
        host_list.append((xml[start:end]))  # Add host XML substring
        xml = xml[:start] + xml[end:]  # Remove substring from data
    # Return list of host XML substrings
    return host_list


def get_info(host_dict: dict) -> HostInfo:
    """Extract information from host XML dictionaries"""
    names = host_dict["hostnames"]
    # Create new HostInfo instance
    info = HostInfo(
        (None if null(names) else names["hostname"]),
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
                    # Parse domain name info
                    for name in names:
                        domain = name.split(":")[1]  # Split label/name
                        if domain != info.IPAddress:
                            info.DomainName = domain
                            break
                elif script["@id"] == "ssl-enum-ciphers":
                    strength = lines[-1][-1]  # Last char of last line

        info.PortList.append((item["@portid"], strength))
    return info  # Return target host info


# Initialize cmd-line arguments parser
parser = argparse.ArgumentParser(
    prog="sslmap.py", add_help=False,
    usage="sslmap.py [-h] [-c CONFIG] [-o OUTPUT] [-p PORT] TARGET",
    description="SSL cipher strength grader (python3)",
)

parser.add_argument(
    "-h", "--help", action="store_true",
    help="show this help message and exit"
)

parser.add_argument(
    "-c", "--config", type=str, nargs="?",
    help="specify the config file path to load",
    default=(Path.cwd() / "config.json")
)

conf, opts, file_dict = (None, None, None)
raw_path = parser.parse_known_args()[0].config

# Parse config path from cmd-line
if null(raw_path):
    conf_path = (Path.cwd() / "config.json").resolve()
else:
    conf_path = Path(raw_path).resolve()

# Use config options if file exists
use_conf = conf_path.exists()

if use_conf:  # Read file data
    with conf_path.open("r") as config:
        json_lines = []
        # Ignore JSON config comments
        for line in config:
            if not line.startswith("//"):
                json_lines.append(line)
        conf = "".join(json_lines)
    # Transform raw JSON data to dictionary
    opts = json.loads(conf)["options"]

    # Combine file names and parent path
    for key, val in opts["fileNames"].items():
        if not null(opts["parent"]):
            full_path = Path(opts["parent"]) / val
        else:
            full_path = Path.cwd() / val
        # Update dictionary with absolute paths
        opts["fileNames"].update({(key, full_path)})

    file_dict = opts["fileNames"]

parser.add_argument(
    "TARGET", type=str, nargs="*",
    help="specify the nmap scan target(s)",
    default=(opts["target"] if use_conf else [])
)

parser.add_argument(
    "-o", "--output", type=str, nargs="?",
    help="specify parent path for CSV output files",
    default=(opts["parent"] if use_conf else Path.cwd())
)

parser.add_argument(
    "-p", "--port", type=str, nargs="?",
    help="specify the scan target port(s)",
    default=(opts["ports"] if use_conf else "443,8443")
)

# Parse cmd-line arguments
args = parser.parse_args()

# Display help and exit
if args.help:
    parser.print_help()
    exit(0)

target = list(args.TARGET)
ports = None if null(args.port) else str(args.port)
parent = Path.cwd() if null(args.output) else Path(args.output)

# Determine if CSV data will dump to console
if parent.name == "-":
    dump_csv = True
    parent = Path.cwd()
    # Load parent path from config file
    if use_conf:
        raw_path = opts["fileNames"]["errors"]
        parent = Path(raw_path).parent.resolve()
else:
    dump_csv = False
    parent = parent.resolve()

# Datetime string format
date_fmt = "%Y/%m/%d %H:%M:%S"

# Nmap (TCP connect) scan parameters
nm_params = (
    "-sT", "-Pn", "-oX", "-", "-p", ports,
    "--script", "ssl-cert,ssl-enum-ciphers"
)

headers = get_headers((
    '"IPAddress"', '"Port"', '"HostName"', '"DomainName"',
    '"OverallRating"', '"StartTime"', '"EndTime"',
))

# Dictionary to store CSV file targets
if file_dict is None:
    dir_path = parent if parent.exists() else Path.cwd()
    file_dict = {
        "upCsv": (dir_path / "scan_up.csv"),
        "downCsv": (dir_path / "scan_down.csv")
    }

# Initialize the error log handler
if parent.exists():
    log = LogHandler(Path(parent / "errors.log").resolve())
else:
    log = LogHandler((Path.cwd() / "errors.log").resolve())

# Main entry point (start user interactions)
if __name__ == "__main__":
    if len(target) == 0:
        log.option("TARGET", "At least one value is required")

    if null(ports):
        log.option("PORT", "An argument value is required")

    # Validate port(s) parsed from cmd-line
    for port in ports.split(","):
        if not port.isdigit():
            log.option("PORT", f"{port} is not an integer")
        elif not (0 <= int(port) <= 65535):
            log.option("PORT", f"Invalid port number {port}")

    # Validate output directory file path
    if dump_csv & (not parent.exists()):
        log.option("OUTPUT", f"Invalid parent path {parent}")

    # Locate Nmap executable file
    exec_path = shutil.which("nmap")
    if exec_path is None:
        log.error(("NmapPath", "Unable to locate Nmap executable"))

    # Skip if CSV output target is console stdout
    if not dump_csv:
        for key, path in file_dict.items():
            if key == "upCsv":
                header = headers["up"]
            elif key == "downCsv":
                header = headers["down"]
            else:
                continue  # Skip error log

            path.touch()
            csv_lines = path.read_text().splitlines()

            # Add CSV field header to file if missing
            if len(csv_lines) == 0:
                path.write_text(header + "\n")
            elif csv_lines[0] != header:
                path.write_text("\n".join((header, *csv_lines, "")))

    print("[*] Beginning scan, this could take a while...")
    raw_xml = run_scan([exec_path, *nm_params, *target])

    host_strings = parse_xml(raw_xml)
    host_count = len(host_strings)

    # Format and print CSV field names
    if dump_csv & (host_count != 0):
        heading = headers["up"].replace('"', "")
        heading = f"\n{heading}\n" + ("-" * len(heading))
        print(heading)

    # Parse host data from each XML string
    for host_xml in host_strings:
        info_dict = XmlTextToDict(host_xml).get_dict()
        new_lines = get_info(info_dict["host"]).to_csv()

        for line in new_lines:
            file_path = None
            fields = line.split("|")
            if dump_csv:
                print(line.replace('"', ""))
                continue  # Skip loop remainder

            # Remove strength field from inactive hosts
            if fields[4] == '""':
                file_path = Path(file_dict["downCsv"])
                fields.pop(4)
            else:
                file_path = Path(file_dict["upCsv"])

            # Append host info to CSV file
            with file_path.open("a") as csv:
                csv.write("|".join(fields) + "\n")

    exit_msg = "[*] SSL scan completed"
    banner = ["", exit_msg] if dump_csv else [exit_msg]

    # Build and display exit banner
    if host_count == 0:
        banner.append(f"    ERRORS: '{log.FilePath}'")
    elif not dump_csv:
        banner.append(f"    OUTPUT (UP): '{file_dict['upCsv']}'")
        banner.append(f"    OUTPUT (DOWN): '{file_dict['downCsv']}'")

    print(*banner, sep="\n")
