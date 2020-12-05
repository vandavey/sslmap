# SSLMap

Python3 - Scan network targets with Nmap to determine SSL cipher strengths.

## Table of Contents

1) [SSLMap](#sslmap)
2) [Table of Contents](#table-of-contents)
3) [Basic Usage](#basic-usage)
4) [Available Arguments](#available-arguments)
5) [Usage Examples](#usage-examples)
    1) [Display Help](#display-help)
    2) [Basic Scans](#basic-scans)
    3) [Custom Scans](#custom-scans)
6) [Installation](#installation)
    1) [Automatic Installation](#automatic-installation)
    2) [Manual Installation](#manual-installation)
        1) [Install Dependencies](#install-dependencies)
        2) [Install SSLMap](#install-sslmap)
7) [Dependencies](#dependencies)
8) [Run as Task](#run-as-task)
9) [Remarks](#remarks)

***

## Basic Usage

The basic usage for SSLMap is described below:

```powershell
sslmap.py [-h] [-c CONFIG] [-o OUTPUT] [-p PORT] TARGET
```

***

## Available Arguments

All available SSLMap command-line arguments are listed below:

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

    Only SSLMap errors are logged when `<OUTPUT>` *equals* `-`.

***

## Installation

There are two methods available to install SSLMap and its
[dependencies](#dependencies):

1) [Automatic installation](#automatic-installation) (*recommended*)
2) [Manual installation](#manual-installation)

***

### Automatic Installation

To automatically install SSLMap and its required dependencies, use *PowerShell*
to download and execute the `install.ps1` installer script.

* Launch a *PowerShell* console, then copy and paste the following code block into
  the console window:

    ```powershell
    $uri = "https://raw.githubusercontent.com/vandavey/sslmap/master/install.ps1"

    try {
        # Download the installer script
        $httpResp = Invoke-WebRequest $uri -Method "GET"

        # Pass script through pipeline to bypass execution policy
        Write-Output $httpResp.Content | powershell.exe -
    }
    catch {
        Write-Output "[x] $((Get-Error).Exception.Message)`n"
    }
    ```

* Use the `ENTER` key to ensure that all lines are properly interpreted
  by *PowerShell*.

* If the server response contains a *HTTP 200* status code, the install
  process will begin. Otherwise, the connection error message will be
  displayed.

***

### Manual Installation

#### Install Dependencies

1) Download and install the dependencies listed in the
   [project dependencies](#dependencies) section.
2) Add the [Python](https://www.python.org/downloads/) and
   [Nmap](https://nmap.org/download.html) executable parent directories to the
   system environment path.
   1) Use the `WINDOWS+R` keyboard shortcut to launch a new *Run* dialog instance.
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

        If the version is displayed, `nmap.exe` was successfully installed.

    * Display the local [Python](https://www.python.org/downloads/) version:

        ```powershell
        python.exe -V
        ```

        If the version is displayed, `python.exe` was successfully installed.

4) Install [XmlToDict3](https://pypi.org/project/xmltodict3/) using *pip*.
    1) Launch a `powershell.exe` console window (running as administrator).
    2) Ensure *pip* is updated before installing new module:

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

       If no warning message is displayed, `XmlToDict` was successfully installed.

#### Install SSLMap

1) Use one of the following methods to clone the SSLMap repository.
    * Use the [git](https://git-scm.com/downloads) command-line application:

        ```powershell
        git clone "https://github.com/vandavey/sslmap.git"
        ```

    * Download a zip archive of the repository by clicking
      [here](https://github.com/vandavey/sslmap/archive/master.zip),
      then extract the archived contents.

2) Add the `sslmap.py` executable parent directory to the system environment
   path (described in step *2* of [install dependencies](#install-dependencies)).

3) Verify that `sslmap.py` has been added to the environment path:
   1) Launch a new `powershell.exe` console window.
   2) View the `sslmap.py` help menu by using the `--help` option:

       ```powershell
       sslmap.py --help
       ```

       If the command executes successfully, `sslmap.py` was successfully
       added to the environment path.

***

## Dependencies

The following packages are required to use SSLMap:

* [Nmap](https://nmap.org/download.html)
* [Python3](https://www.python.org/downloads/)
  * [xmltodict3](https://pypi.org/project/xmltodict3/)

Once installed, ensure the executable parent directories exist on the
environment path (see *step 2* of [install dependencies](#install-dependencies)).

***

## Run as Task

To run SSLMap as an automated task, use the built-in *Windows Task Scheduler*.

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
and `sslmap.py` **must** be added to the local environment path variable (see
*step 2* of [install dependencies](#install-dependencies)).

***

## Remarks

* All instructions described in this file are intended for users
  running a *Windows* flavored operating system.
