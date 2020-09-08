# sslmap

Python 3 - Scan network targets with Nmap to determine SSL cipher strengths.

## Arguments

| Argument             | Type       | Description              | Defaults    |
|:--------------------:|:----------:|:------------------------:|:-----------:|
| `TARGET`             | *Required* | Nmap scan target(s)      | *N/A*       |
| `-p/--port PORT`     | *Optional* | Nmap scan target port(s) | *443, 8443* |
| `-o/--output OUTPUT` | *Optional* | File path for CSV output | *scan.csv*  |
| `-h, --help`         | *Optional* | Display help menu        | *False*     |

## Basic Usage

```bat
sslmap.py [-h] [-o OUTPUT] [-p PORT] TARGET
```

## Usage Examples

### Display Help

Display the program help menu, then exit.

```bat
sslmap.py --help
```

### Basic Scans

* Scan a single IPv4 address:

    ```bat
    sslmap.py 192.168.1.1
    ```

* Scan an entire IPv4 address range:
  
    ```bat
    sslmap.py 192.168.1.0/24
    ```

* Scan multiple target hosts at once:

    ```bat
    sslmap.py 192.168.1.1 10.0.0.53
    ```

### Advanced Scans

* Specify custom target port(s):

    ```bat
    sslmap.py -p 80,443 192.168.1.1
    ```

    > *Note*: For multiple ports, join each port with a comma (*no spaces*)

* Write CSV data to custom file path:

    ```bat
    sslmap.py -o C:\scan_data.csv 192.168.1.1
    ```

    > *Note*: New data will be appended if file exists at `<OUTPUT>`

* Dump CSV data to console standard output:

    ```bat
    sslmap.py --output -
    ```

    > *Note*: No data is written to file when `<OUTPUT>` *equals* `-`

## Run as Task

To run ***sslmap*** as an automated task, use the built-in *Windows Task Scheduler*.

1. Launch *Windows Task Scheduler* (taskschd.msc).
2. Select *Create Task* from the *Actions* pane on the right.
3. Specify the task *Name* and navigate to the *Triggers* tab, then click *New*.
4. Specify the desired run frequency/schedule options, then click *OK*.
5. Navigate to the *Actions* tab and click *New*.
6. Verify that the *Start a program* option is selected in the *Action* dropdown.
7. In the *Program/script* field, specify the absolute file path to `sslmap.py`.
8. Add any additional execution arguments in the *Add arguments* field.
9. Click *OK* to confirm the *Action* options, then click *OK* again to save the task.

## Project Dependencies

The following packages are required to use ***sslmap***:

* [Nmap](https://nmap.org/download.html)
* [Python3](https://www.python.org/downloads/)
  * [python3-nmap](https://pypi.org/project/python3-nmap/)
  * [xmltodict3](https://pypi.org/project/xmltodict3/)

*Note:* Once [Python](https://www.python.org/downloads/) and [Nmap](https://nmap.org/download.html)
are installed, ensure the executable parent directories are added to the local environment path.
It is also helpful to place `sslmap.py` on environment the path.
