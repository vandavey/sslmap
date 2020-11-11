# SSLMap

Python3 - Scan network targets with Nmap to determine SSL cipher strengths.

## Basic Usage

```powershell
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

[//]: # (TODO: update usage examples with new arguments)

### Display Help

* Display the program help menu, then exit:

    ````powershell
    sslmap.py --help
    ````

### Basic Scans

* Scan a single IPv4 address:

    ```powershell
    sslmap.py "192.168.1.1"
    ```

* Scan an entire IPv4 address range:
  
    ```powershell
    sslmap.py "192.168.1.0/24"
    ```

* Scan multiple target hosts at once:

    ```powershell
    sslmap.py "192.168.1.1" "10.0.0.53"
    ```

### Custom Scans

* Specify custom target port(s):

    ```powershell
    sslmap.py -p 80,443 "192.168.1.1"
    ```

    For multiple ports, join each port with a comma (*no spaces*).

* Write CSV data to custom file path:

    ```powershell
    sslmap.py -o "C:\scan_data.csv" "192.168.1.1"
    ```

    New data will be appended if file exists at `<OUTPUT>`.

* Dump CSV data to console standard output:

    ```powershell
    sslmap.py --output -
    ```

    Only **sslmap** errors are logged when `<OUTPUT>` *equals* `-`.

***

## Run as Task

To run **sslmap** as an automated task, use the built-in *Windows Task Scheduler*.

1) Launch *Windows Task Scheduler* (taskschd.msc).
2) Select *Create Task* from the *Actions* pane on the right.
3) Navigate to the *General* tab of the window.
    * Specify the task *Name*.
    * Specify the task *Description* (optional).
4) Navigate to the *Triggers* tab, then click *New*.
    * Specify the desired scan scheduling options, then click *OK*.
5) Navigate to the *Actions* tab and click *New*.
    * Verify that the *Start a program* option is selected in the *Action* dropdown.
    * In the *Program/script* field, specify the path to the system `python` executable.
    * In the *Add arguments* field, add `sslmap.py` followed by any other run options.
    * Specify the `sslmap.py` parent directory path in the *Start in* field.
    * Click *OK* to confirm the *Action* options.
6) Click *OK* again to save the task.

In order for these steps to work as expected, the parent directories of
[Python](https://www.python.org/downloads/), [Nmap](https://nmap.org/download.html),
and `sslmap.py` **must** be added to the local environment path variable (see the
[dependencies](#dependencies) section of the [installation guide](#installation-guide)).  

***

## Project Dependencies

The following packages are required to use **sslmap**:

* [Nmap](https://nmap.org/download.html)
* [Python3](https://www.python.org/downloads/)
  * [xmltodict3](https://pypi.org/project/xmltodict3/)

Once installed, ensure the executable parent directories exist on the
environment path (see the [installation guide](#installation-guide) and
[miscellaneous](#miscellaneous)).

***

## Installation Guide

### Dependencies

1) Download and install the dependencies listed in the
   [project dependencies](#project-dependencies) section above.
2) Add the [Python](https://www.python.org/downloads/) and
   [Nmap](https://nmap.org/download.html) executable parent directories to the
   system environment path.
   1) Use the *Windows+R* keyboard shortcut to launch a new *Run* dialog instance.
   2) In the *Run* dialog, type `sysdm.cpl` to launch the *System Properties*
      control panel window.
   3) Switch to the *Advanced* tab at the top of the *System Properties* window.
   4) Click the button labeled *Environment Variables*.
   5) In the *User variables* section, highlight *Path* and click *Edit*.
   6) Click the *New* button in the *Edit environment variable* window.
   7) Type the filepath of the parent directory that contains the executable.
   8) Click *OK* to save the updated environment variables.
   9) Click *OK* again to write the changes to the system registry.

3) Verify system environment path executable access.
    * Display the local [Nmap](https://nmap.org/download.html) version:

         ```powershell
         nmap.exe -V
         ```

        If the version is displayed, `nmap.exe` was successfully added.

    * Display the local [Python](https://www.python.org/downloads/) version:

        ```powershell
        python.exe -V
        ```

        If the version is displayed, `python.exe` was successfully added.

4) Install [XmlToDict3](https://pypi.org/project/xmltodict3/) using `pip`.
    1) Launch a `powershell.exe` console window (running as administrator).
    2) Ensure pip is updated before installing new module:

        ```powershell
       python.exe -m pip install -U pip
        ```

    3) Install the [XmlToDict3](https://pypi.org/project/xmltodict3/) module:

        ```powershell
       python.exe -m pip install -U xmlTodict3
        ```

    4) Verify that the installation was successful:

        ```powershell
       python.exe -m pip show xmlTodict3
        ```

       If no warning message is displayed, the installation was successful.

### Application

1) Use one of the following methods to clone the SSLMap repository.
    * Use the [git](https://git-scm.com/downloads) command-line application:

        ```powershell
        git clone "https://github.com/vandavey/sslmap.git"
        ```

    * Download a zip archive of the repository by clicking
      [here](https://github.com/vandavey/sslmap/archive/master.zip),
      then extract the archived contents.

2) Add the `sslmap.py` executable parent directory to the system environment
   path (see the [dependencies](#dependencies) section of the
   [installation guide](#installation-guide)).

3) Verify that`sslmap.py` has been added to the environment path:
   1) Launch a new `powershell.exe` console window.
   2) View the `sslmap.py` help menu by using the `--help` option:

       ```powershell
       sslmap.py --help
       ```

       If the command executes successfully, `sslmap.py`
       was successfully added to the environment path.

***

## Miscellaneous

[//]: # (TODO: mention troubleshooting & config file resets)

* Use *PowerShell* to verify that all dependencies are satisfied
  and that `sslmap.py` is accessible through the environment path:

    ```powershell
    if (-Not $(nmap.exe -V)) {
        Write-Output "[x] Unable to locate nmap.exe"
        return
    }

    if (-Not $(python.exe -V)) {
        Write-Output "[x] Unable to locate python.exe"
        return
    }

    if (-Not $(python.exe -m pip show xmltodict3)) {
        Write-Output "[x] Unable to locate pip module XmlToDict3"
        return
    }

    if (-Not $(sslmap.py --help)) {
        Write-Output "[x] Unable to locate sslmap.py"
        return
    }

    Write-Output "[*] All SSLMap dependencies installed successfully"
    ```

    If there are no errors or warnings displayed, all packages are
    installed correctly.
