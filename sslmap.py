#!/usr/bin/env python3
import argparse
import copy
import json
import logging
import os
import shutil
import subprocess
from datetime import datetime
from json.decoder import JSONDecodeError
from pathlib import Path
from xmltodict3 import XmlTextToDict

# TODO: Update README with new information
# TODO: test and debug [-c -] option


class LogHandler(object):
    """Class to handle error logging operations"""
    def __init__(self, path=(Path.cwd() / "errors.log")):
        global date_fmt
        handler = logging.FileHandler(path, "a")

        # Set msg/date formats of error logger
        handler.setFormatter(logging.Formatter(
            fmt="[%(asctime)s.%(msecs)d] %(message)s",
            datefmt=date_fmt
        ))
        # Initialize properties
        self.FilePath = path
        self.Logger = logging.getLogger("errors")  # New logger
        self.Logger.addHandler(handler)  # Add log file handler
        self.Logger.setLevel(logging.ERROR)  # Only log errors

    def _handle(self, err: str, kill: bool, quiet: bool) -> None:
        """Protected helper method. Call self.error/self.option to
        append info to the log file instead of this method."""
        if not quiet:
            print(f"[x] {err} (see errors.log for details)")

        self.Logger.error(err)  # Write to log file
        if kill:
            exit(1)  # Exit SSLMap

    def option(self, opt: str, err: str, quiet=False) -> None:
        """Log invalid cmd-line/config option and exit SSLMap"""
        global parser
        if not quiet:
            print(f"usage: {parser.usage}")

        self._handle(f"OPTION ({opt}): {err}", True, quiet)

    def error(self, exc, close=True) -> None:
        """Log general error to file and (optionally) exit SSLMap"""
        if Exception in type(exc).mro():  # if python exception
            err = f"ERROR ({type(exc).__name__}): {exc.args[0]}"
        else:
            err = f"ERROR ({exc[0]}): {exc[1]}"

        self._handle(err, close, quiet=False)


class HostInfo(object):
    """Class to store scan data specific to each target host"""
    def __init__(self, name_info, ip_info, stamps: tuple):
        name_type = type(name_info)
        if name_type is list:
            self.HostName = name_info[0]["@name"]  # [0]= Most common
        elif name_type is dict:
            self.HostName = name_info["@name"]
        else:
            self.HostName = None

        # Ensure <ip_info> is iterable
        ip_items = ip_info if (type(ip_info) is list) else [ip_info]
        for item in ip_items:
            if item["@addrtype"] == "ipv4":
                self.IPAddress = item["@addr"]
                break

        # Parse timestamps, initialize remaining properties
        self.StartTime = self.to_datetime(int(stamps[0]))
        self.EndTime = self.to_datetime(int(stamps[1]))
        self.DomainName = None
        self.PortList = []

    @staticmethod
    def to_datetime(time_stamp: int) -> str:
        """Convert Unix epoch timestamp to datetime string"""
        global date_fmt
        return datetime.fromtimestamp(time_stamp).strftime(date_fmt)

    def to_csv(self) -> list:
        """Format and return host info as CSV record entries.
        Each additional port adds an item to the list returned."""
        records = []
        for (port_num, strength) in self.PortList:
            records.append(",".join((
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


def parse_json(json_path: Path, backup: bool) -> dict:
    """Parse JSON data from file and return as dictionary"""
    global js_data, file_bak
    js_data = json_path.read_text()  # File data
    if backup:
        file_bak = str(js_data)  # Unmodified backup

    # Remove all JSON block comments
    if js_data.count("/*") > 0:
        for c in range(js_data.count("/*")):
            start = js_data.find("/*")
            stop = js_data.find("*/") + len("*/")
            if start > -1:
                js_data = js_data[:start] + js_data[stop:]

    # Remove inline JSON comments
    if js_data.count("//") > 0:
        for c in range(js_data.count("//")):
            start = js_data.find("//")
            stop = js_data.find("\n", start, -1) + len("\n")
            if start > -1:
                js_data = js_data[:start] + js_data[stop:]

    # Initialize/return new JSON dictionaries
    try:
        return json.loads(js_data)  # Transform string to dict
    except JSONDecodeError:
        err = f"'{json_path.name}' contains invalid JSON data"
        LogHandler().error(("JSONDecodeError", err))


def get_headers() -> dict:
    """Get CSV file header up/down hosts dictionary"""
    names = (
        '"IPAddress"', '"Port"', '"HostName"', '"DomainName"',
        '"OverallRating"', '"StartTime"', '"EndTime"',
    )
    return {
        "up": ",".join(names),
        "down": ",".join((*names[:4], *names[5:]))
    }


def run_scan(targets: list, nm_args: tuple) -> list:
    """Execute Nmap scan and return XML output list"""
    global conf, log, use_conf
    xml_list = []
    err_detected = False

    # Scan targets separately in case interrupted
    for nm_targ in targets:
        nm_stats = None
        try:
            nm_stats = subprocess.run(
                args=(*nm_args, nm_targ),  # Nmap cmd-line args
                stdin=subprocess.PIPE,  # Nmap standard input
                stdout=subprocess.PIPE,  # Nmap standard output
                stderr=subprocess.PIPE,  # Nmap standard error
                encoding="utf-8"  # Out text instead of bytes
            )
        except Exception as nm_ex:
            err_detected = True
            log.error(nm_ex, close=False)

        # Don't exit on error (replicate Nmap behavior)
        if nm_stats.stderr != "":
            for error in nm_stats.stderr.splitlines():
                nm_error = error[:-1].split(": ")  # Split label/msg

                # Handle warnings and errors
                if nm_error[0] == "WARNING":
                    print(f"[!] NMAP: {nm_error[1]}")
                elif "-Pn" not in nm_error[0]:
                    log.error(("Nmap", nm_error[0]), close=False)

        # Update config 'lastTarget' value
        if use_conf:
            conf["lastRunStats"].update({"lastTarget": nm_targ})

        # Parse the host XML substring data
        if err_detected is False:
            beg = nm_stats.stdout.find("<host")
            end = nm_stats.stdout.find("</host>") + len("</host>")
            xml = nm_stats.stdout[beg:end]
            if not null(xml):
                xml_list.append(xml.replace("\r", "").replace("\n", ""))

    return xml_list  # Return XML strings


def get_info(host_dict: dict) -> HostInfo:
    """Extract information from host XML dictionaries"""
    if not null(host_dict["hostnames"]):
        host_name = host_dict["hostnames"]["hostname"]
    else:
        host_name = None

    # Ensure ports are iterable
    if type(host_dict["ports"]["port"]) is not list:
        port_info = [host_dict["ports"]["port"]]
    else:
        port_info = host_dict["ports"]["port"]

    # Initialize HostInfo object
    info = HostInfo(
        host_name, host_dict["address"],
        (host_dict["@starttime"], host_dict["@endtime"])
    )
    # Extract port and NSE script info
    for item in port_info:
        strength = None
        if "script" in item.keys():  # Skip if NSE not used
            for script in item["script"]:
                lines = script["@output"].replace(",", "").splitlines()
                if script["@id"] == "ssl-cert":
                    names = lines[1].split()
                    names = [n for n in names if ("DNS" in n)]
                    for name in names:  # Parse domain info
                        domain = name.split(":")[1]  # Split label/name
                        if domain != info.IPAddress:
                            info.DomainName = domain
                            break  # Break domain name loop
                elif script["@id"] == "ssl-enum-ciphers":
                    strength = lines[-1][-1]  # Last char of last line

        # Append tuple containing port info (Port, Strength)
        info.PortList.append((item["@portid"], strength))
    return info  # Return HostInfo object


# Default install directory path
parent = Path(os.getenv("LOCALAPPDATA")) / "sslmap"

# Initialize cmd-line argument parser
parser = argparse.ArgumentParser(
    prog="sslmap.py", add_help=False,
    usage="sslmap.py [-h] [-c CONFIG] [-o OUTPUT] [-p PORT] TARGET",
    description="SSL cipher strength grader (python3)",
)

# Override default help (wasn't reading all args)
parser.add_argument(
    "-h", "--help", action="store_true",
    help="show this help message and exit"
)

parser.add_argument(
    "-c", "--config", type=str, nargs="?",
    help="specify the config file path to load",
    default=(parent / "config.json")
)

# Initialize global variables
conf, opts, stats = (None, None, None)
file_dict, js_data, incomplete = (None, None, [])

date_fmt = "%Y/%m/%d %H:%M:%S"  # Date-time format
known_args = parser.parse_known_args()[0]
raw_path = known_args.config

# Convert raw config path to Path object
if null(raw_path):
    conf_path = parent / "config.json"
else:
    conf_path = Path(raw_path).resolve()
    if (not known_args.help) & (not conf_path.exists()):
        msg = f"Unable to locate file '{conf_path.name}'"
        LogHandler().option("CONFIG", msg)

# Use config options if file exists
use_conf = conf_path.exists()
file_bak, opts_bak, json_bak = (None, None, None)

if use_conf:
    conf = parse_json(conf_path, True)  # Config dict
    opts = conf["options"]  # Config options

    opts_bak = copy.deepcopy(opts)  # Config options backup
    json_bak = js_data[1:-1]  # Existing JSON substring backup

    # Combine file names and parent path
    for (key, val) in opts["fileNames"].items():
        if not null(opts["parent"]):
            full_path = Path(opts["parent"]) / val
        else:
            full_path = parent / val

        # Update dictionary with absolute paths
        opts["fileNames"].update({key: full_path})

    file_dict = opts["fileNames"]  # File name/path dict
    stats = conf["lastRunStats"]  # Scan statistics

    # Include scan targets that were interrupted
    if opts["resume"] & (not stats["completed"]):
        if stats["lastTarget"] != stats["lastTarget"][-1]:
            index = stats["target"].index(stats["lastTarget"])
            incomplete = stats["target"][index:]

parser.add_argument(
    "TARGET", type=str, nargs="*",
    help="specify the nmap scan target(s)",
    default=(opts["target"] if use_conf else [])
)

parser.add_argument(
    "-o", "--output", type=str, nargs="?",
    help="specify parent path for CSV output files",
    default=(opts["parent"] if use_conf else parent)
)

parser.add_argument(
    "-p", "--port", type=str, nargs="?",
    help="specify the scan target port(s)",
    default=(opts["ports"] if use_conf else "443,8443")
)

# Parse cmd-line arguments
args = None
try:
    args = parser.parse_args()
except SystemExit:
    msg = "Unrecognized argument was received"
    LogHandler().option("UNKNOWN", msg, quiet=True)

# Print help and exit
if args.help:
    parser.print_help()
    exit(0)

target = list(args.TARGET)
ports = None if null(args.port) else str(args.port)
parent = parent if null(args.output) else Path(args.output)

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

# Dictionary to store CSV file targets
if null(file_dict):
    dir_path = parent if parent.exists() else Path.cwd()
    file_dict = {
        "upCsv": (dir_path / "scan_up.csv"),
        "downCsv": (dir_path / "scan_down.csv")
    }

# Validate error log file path
if parent.exists():
    log_path = Path(parent / "errors.log").resolve()
else:
    log_path = Path(Path.cwd() / "errors.log").resolve()

# Initialize log handler
log = LogHandler(log_path)
headers = get_headers()  # CSV field headers
targ_path = None

# Update scan stats 'errors' with log path
if use_conf:
    conf["lastRunStats"].update({"errors": str(log_path)})

# Nmap (TCP connect) scan parameters
nm_params = (
    "-sT", "-Pn", "-oX", "-", "-p", ports,
    "--system-dns", "--script", "ssl-cert,ssl-enum-ciphers"
)

# sslmap.py main entry point
if __name__ == "__main__":
    # Validate target config/arguments
    if len(target) == 0:
        log.option("TARGET", "At least one value is required")

    # Validate target config/arguments
    if len(target) == 1:
        targ_path = Path(str(target[0])).resolve()

        # Load json target file
        if target[0].endswith(".json"):
            if not targ_path.exists():
                msg = f"Unable to locate target file '{targ_path}'"
                log.option("TARGET", msg)

            # Parse target.json
            target = parse_json(targ_path, False)["target"]

        if use_conf & opts["resume"]:
            target = [*incomplete, *target]

    if null(ports):
        log.option("PORT", "An argument value is required")

    # Validate port(s) parsed from cmd-line
    for port in ports.split(","):
        if not port.isdigit():
            log.option("PORT", f"'{port}' is not an integer")
        elif not (0 <= int(port) <= 65535):
            log.option("PORT", f"Invalid port number '{port}'")

    # Validate output directory file path
    if dump_csv & (not parent.exists()):
        log.option("OUTPUT", f"Invalid parent path '{parent}'")

    # Locate Nmap executable file
    exec_path = shutil.which("nmap")
    if null(exec_path):
        log.error(("Nmap", "Unable to locate Nmap executable"))

    # Skip if CSV output target is console stdout
    if not dump_csv:
        for (key, f_path) in file_dict.items():
            if key == "upCsv":
                header = headers["up"]
            elif key == "downCsv":
                header = headers["down"]
            else:
                continue  # Skip error log

            f_path.touch()  # Create file if not found
            csv_lines = f_path.read_text().splitlines()

            # Add CSV field header to file if missing
            if len(csv_lines) == 0:
                f_path.write_text(header + "\n")
            elif csv_lines[0] != header:
                f_path.write_text("\n".join((header, *csv_lines, "")))

    print("[*] Beginning scan, this might take a while...")

    host_strings = run_scan(target, (exec_path, *nm_params))
    host_count = len(host_strings)

    # Format and print CSV field names
    if dump_csv & (host_count > 0):
        heading = headers["up"].replace('"', "").replace(",", "|")
        heading = f"\n{heading}\n" + ("-" * len(heading))
        print(heading)

    # Parse host data from each XML string
    for host_xml in host_strings:
        info_dict = XmlTextToDict(host_xml).get_dict()
        new_lines = get_info(info_dict["host"]).to_csv()

        for line in new_lines:
            file_path = None
            fields = line.split(",")
            if dump_csv:
                print(line.replace('"', "").replace(",", "|"))
                continue  # Skip to next iteration

            # Remove strength field from inactive hosts
            if fields[4] == '""':
                file_path = Path(file_dict["downCsv"])
                fields.pop(4)
            else:
                file_path = Path(file_dict["upCsv"])

            # Append host info to CSV file
            with file_path.open("a") as csv:
                csv.write(",".join(fields) + "\n")

    # Update config scan statistics
    if use_conf:
        new_conf = {"title": "config", "options": opts_bak}
        stats.update({"target": target})

        # Update scan completion information
        if stats["target"][-1] == stats["lastTarget"]:
            stats.update({"completed": True, "lastTarget": None})
        else:
            stats.update({"completed": False})

        # Add scan info to config dictionary
        new_conf.update({"lastRunStats": stats})
        new_json = json.dumps(new_conf, indent=4)  # Output string

        # Replace existing config JSON data w/ new info
        new_data = file_bak.replace(json_bak, new_json)
        conf_path.write_text(new_data)  # Overwrite file data

    # Build exit banner
    exit_msg = "[*] SSL scan completed"
    banner = ["", exit_msg] if dump_csv else [exit_msg]

    if host_count == 0:
        banner.append(f"    Errors: '{log.FilePath}'")
    elif not dump_csv:
        banner.append(f"    CSV [Up]: '{file_dict['upCsv']}'")
        banner.append(f"    CSV [Down]: '{file_dict['downCsv']}'")

    print(*banner, sep="\n")  # Display exit banner
