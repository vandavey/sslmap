# SSLMap

Python3 - Scan network targets with Nmap to determine SSL cipher strengths.

## Basic Usage

```bat
sslmap.py [-h] [-c CONFIG] [-o OUTPUT] [-p PORT] TARGET
```

## Available Arguments

All available **sslmap** command-line arguments are listed below:

| Arguments            | Type       | Description              | Defaults      |
|:--------------------:|:----------:|:------------------------:|:-------------:|
| `TARGET`             | *Required* | Nmap scan target(s)      | *N/A*         |
| `-p/--port PORT`     | *Optional* | Nmap scan target port(s) | *443, 8443*   |
| `-o/--output OUTPUT` | *Optional* | Output parent directory  | *scan.csv*    |
| `-c/--config CONFIG` | *Optional* | Configuration file path  | *config.json* |
| `-h, --help`         | *Optional* | Display help menu        | *False*       |

***

## Usage Examples

### Display Help

Display the program help menu, then exit:

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

### Custom Scans

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

    > *Note*: Only **sslmap** errors be logged when `<OUTPUT>` *equals* `-`

***

## Run as Task

To run **sslmap** as an automated task, use the built-in *Windows Task Scheduler*.

1. Launch *Windows Task Scheduler* (taskschd.msc).
2. Select *Create Task* from the *Actions* pane on the right.
3. Navigate to the *General* tab of the window.
    * Specify the task *Name*.
    * Specify the task *Description* (optional).
4. Navigate to the *Triggers* tab, then click *New*.
    * Specify the desired scan scheduling options, then click *OK*.
5. Navigate to the *Actions* tab and click *New*.
    * Verify that the *Start a program* option is selected in the *Action* dropdown.
    * In the *Program/script* field, specify the path to the system `python` executable.
    * In the *Add arguments* field, add `sslmap.py` followed by any other run options.
    * Specify the `sslmap.py` parent directory path in the *Start in* field.
    * Click *OK* to confirm the *Action* options.
6. Click *OK* again to save the task.

> *Note*: In order for these steps to work as expected, the parent directories of
[Python](https://www.python.org/downloads/), [Nmap](https://nmap.org/download.html),
and `sslmap.py` **must** be added to the local environment path variable.

***

## Project Dependencies

The following packages are required to use **sslmap**:

* [Nmap](https://nmap.org/download.html)
* [Python3](https://www.python.org/downloads/)
  * [xmltodict3](https://pypi.org/project/xmltodict3/)

*Note:* Once [Python](https://www.python.org/downloads/) and
[Nmap](https://nmap.org/download.html) are installed, ensure the executable
parent directories are added to the local environment path. The `sslmap.py`
parent directory should also be added to the local environment path.
