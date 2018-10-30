# SnappyCap
### Cloud-based PCAP analysis; powered by PacketTotal.com

## Description
SnappyCap is a set of scripts and libraries for capturing and analyzing packet captures with PacketTotal.com.
Currently this library provides two scripts:

  - `capture-and-analyze.py` - Capture on an interface for some period of time, and upload capture for analysis.
  - `upload-and-analyze.py` - Upload and analyze multiple packet captures to PacketTotal.com.


```
THESE TOOLS LEVERAGES PACKETTOTAL.COM FOR ANALYSIS. ALL PACKET CAPTURES ANALYZED WITH THESE TOOLS WILL BE MADE PUBLIC UPON ANALYSIS.
```


## Use Cases

1. Analyze a personal repository of malicious PCAPs.
4. Determine the benignity of hundreds of packet captures.
2. Automate analyzing (and sharing) honeypot packet captures.
3. Automate preliminary malware analysis/triage.



## Prerequisites:
 - [WireShark](https://www.wireshark.org/download.html) must be installed.
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

Capture, upload and analyze network traffic; powered by PacketTotal.com.

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