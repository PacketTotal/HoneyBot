# SnappyCap

## Description
SnappyCap is a set of scripts and libraries for capturing and analyzing packet captures with PacketTotal.com.
Currently this library provides two scripts:

  - `capture-and-analyze.py` - Capture on an interface for some period of time, and upload capture for analysis.
  - `upload-and-analyze.py` - Upload and analyze multiple packet captures to PacketTotal.com.

`DISCLAIMER: THESE TOOLS LEVERAGES PACKETTOTAL.COM FOR ANALYSIS. ALL PACKET CAPTURES ANALYZED WITH THIS TOOL WILL BE MADE PUBLIC UPON ANALYSIS.`

## Prerequisites:
 - [WireShark](https://www.wireshark.org/download.html) must be installed.
 - [Python 3.5](https://www.python.org/downloads/) or later is required.
 - You must [request your IP be whitelisted](https://goo.gl/forms/qRE67TO1MC5pual22), before you can leverage these scripts.