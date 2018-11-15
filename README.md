# SnappyCap
### Cloud-based PCAP analysis; powered by PacketTotal.com
![PacketTotal Labs](https://raw.githubusercontent.com/PacketTotal/SnappyCap/master/img/packettotal.png)

## Description
SnappyCap is a set of scripts and libraries for capturing and analyzing packet captures with PacketTotal.com.
Currently this library provides three scripts:

  - `capture-and-analyze.py` - Capture on an interface for some period of time, and upload capture for analysis.
  - `upload-and-analyze.py` - Upload and analyze multiple packet captures to PacketTotal.com.
  - `trigger-and-analyze.py` - Listen for unknown connections, and begin capturing when one is made. Captures are automatically uploaded and analyzed.


## Warning
> Any packet capture uploaded to becomes publicly available upon completed analysis.

## Limitations
- Only .pcap and .pcapng files supported.
- 50 MB analysis max.

For more information visit [PacketTotal.com](https://packettotal.com/about.html).

## Use Cases
1. Set your honeypot up to stream network traffic directly to PacketTotal.com for analysis.
2. Analyze a personal repository of malicious PCAPs.
3. Determine the benignity of hundreds of packet captures.
4. Automate analyzing (and sharing) honeypot packet captures.
5. Automate preliminary malware analysis/triage.



## Prerequisites:
 - [WireShark](https://www.wireshark.org/download.html) must be installed.
    - If you are on a linux based operating system you can just install t-shark
        - `apt-get install tshark`
 - [Python 3.5](https://www.python.org/downloads/) or later is required.
 - You must [request your IP be whitelisted](https://goo.gl/forms/qRE67TO1MC5pual22), before you can leverage these scripts.


## Installation
- `pip install -r requirements.txt`
- `python setup.py install`


## Usage

### capture-and-analyze.py

```
usage: capture-and-analyze.py [-h] [--seconds SECONDS] [--interface INTERFACE]
                              [--analyze] [--list-interfaces] [--list-pcaps]
                              [--export-pcaps]

Capture, upload and analyze network traffic; powered by PacketTotal.com.

optional arguments:
  -h, --help            show this help message and exit
  --seconds SECONDS     The number of seconds to capture traffic for.
  --interface INTERFACE
                        The name of the interface (--list-interfaces to show
                        available)
  --analyze             If included, capture will be uploaded for analysis to
                        PacketTotal.com.
  --list-interfaces     Lists the available interfaces.
  --list-pcaps          Lists pcaps submitted to PacketTotal.com for analysis.
  --export-pcaps        Writes pcaps submitted to PacketTotal.com for analysis
                        to a csv file.
```


### upload-and-analyze.py

```
usage: upload-and-analyze.py [-h] [--path PATH [PATH ...]] [--analyze]
                             [--list-pcaps] [--export-pcaps]

Upload and analyze .pcap/.pcapng files in bulk; powered by PacketTotal.com.

optional arguments:
  -h, --help            show this help message and exit
  --path PATH [PATH ...]
                        One or more paths to pcap or directory of pcaps.
  --analyze             If included, capture will be uploaded for analysis to
                        PacketTotal.com.
  --list-pcaps          Lists pcaps submitted to PacketTotal.com for analysis.
  --export-pcaps        Writes pcaps submitted to PacketTotal.com for analysis
                        to a csv file.
```


### trigger-and-analyze.py
```
usage: trigger-and-analyze.py [-h] [--interface INTERFACE] [--learn LEARN]
                              [--listen] [--capture-seconds CAPTURE_SECONDS]
                              [--list-interfaces] [--list-pcaps]
                              [--export-pcaps]

Listen for unknown connections, and begin capturing when one is made. Captures
are automatically uploaded and analyzed; powered by PacketTotal.com

optional arguments:
  -h, --help            show this help message and exit
  --interface INTERFACE
                        The name of the interface (--list-interfaces to show
                        available)
  --learn LEARN         The number of seconds from which to build the known
                        connections whitelist. Connections in this whitelist
                        will be ignored.
  --listen              If included, we will begin listening for unknown
                        connections, and immediately starting a packet capture
                        and uploading to PacketTotal.com for analysis.
  --capture-seconds CAPTURE_SECONDS
                        The number of seconds worth of network traffic to
                        capture and analyze after a trigger has fired.
  --list-interfaces     Lists the available interfaces.
  --list-pcaps          Lists pcaps submitted to PacketTotal.com for analysis.
  --export-pcaps        Writes pcaps submitted to PacketTotal.com for analysis
                        to a csv file.
```

