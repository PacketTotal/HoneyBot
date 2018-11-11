"""
__author__: Jamin Becker (jamin@packettotal.com)
"""


import logging
import os
import pathlib
import sys
import time
import warnings
from hashlib import md5

import progressbar
import psutil
import pyshark
from magic import from_buffer
from terminaltables import AsciiTable

from snappycap.lib import const


def capture_on_interface(interface, name, timeout=60):
    """
    :param interface: The name of the interface on which to capture traffic
    :param name: The name of the capture file
    :param timeout: A limit in seconds specifying how long to capture traffic
    """

    if timeout < 15:
        logger.error("Timeout must be over 15 seconds.")
        return
    if not sys.warnoptions:
        warnings.simplefilter("ignore")
    start = time.time()
    widgets = [
        progressbar.Bar(marker=progressbar.RotatingMarker()),
        ' ',
        progressbar.FormatLabel('Packets Captured: %(value)d'),
        ' ',
        progressbar.Timer(),
    ]
    progress = progressbar.ProgressBar(widgets=widgets)
    capture = pyshark.LiveCapture(interface=interface, output_file=os.path.join('tmp', name))
    pcap_size = 0
    for i, packet in enumerate(capture.sniff_continuously()):
        progress.update(i)
        if os.path.getsize(os.path.join('tmp', name)) != pcap_size:
            pcap_size = os.path.getsize(os.path.join('tmp', name))
        if not isinstance(packet, pyshark.packet.packet.Packet):
            continue
        if time.time() - start > timeout:
            break
        if pcap_size > const.PT_MAX_BYTES:
            break
    capture.clear()
    capture.close()
    return pcap_size


def get_filepath_md5_hash(file_path):
    """
    :param file_path: path to the file being hashed
    :return: the md5 hash of a file
    """
    with open(file_path, 'rb') as afile:
       return get_file_md5_hash(afile)


def get_file_md5_hash(fh):
    """
    :param fh: file handle
    :return: the md5 hash of the file
    """
    block_size = 65536
    md5_hasher = md5()
    buf = fh.read(block_size)
    while len(buf) > 0:
        md5_hasher.update(buf)
        buf = fh.read(block_size)
    return md5_hasher.hexdigest()


def get_network_interfaces():
    """
    :return: A list of valid interfaces and their addresses
    """
    return psutil.net_if_addrs().items()


def is_packet_capture(bytes):
    """
    :param bytes: raw bytes
    :return: True is valid pcap or pcapng file
    """
    result = from_buffer(bytes)
    return "pcap-ng" in result or "tcpdump" in result or "NetMon" in result


def mkdir_p(path):
    """
    :param path: Path to the new directory to create
    """

    pathlib.Path(path).mkdir(parents=True, exist_ok=True)


def listen_on_interface(interface, timeout=60):
    """
    :param interface: The name of the interface on which to capture traffic
    :return: generator containing live packets
    """

    start = time.time()
    capture = pyshark.LiveCapture(interface=interface)

    for item in capture.sniff_continuously():
        if timeout and time.time() - start > timeout:
            break
        yield item



def print_network_interaces():
    """
    :return: Prints a human readable representation of the available network interfaces
    """

    for intf, items in get_network_interfaces():
        table = [["family", "address", "netmask", "broadcast", "ptp"]]
        for item in items:
            family, address, netmask, broadcast, ptp = item
            table.append([str(family), str(address), str(netmask), str(broadcast), str(ptp)])
        print(AsciiTable(table_data=table, title=intf).table)
        print('\n')


def print_analysis_disclaimer():
    print("""
        WARNING: Analysis will result in the network traffic becoming public at https://packettotal.com.
        
        ADVERTENCIA: El análisis hará que el tráfico de la red se haga público en https://packettotal.com.
        
        WARNUNG: Die Analyse führt dazu, dass der Netzwerkverkehr unter https://packettotal.com öffentlich wird.
        
        ПРЕДУПРЕЖДЕНИЕ. Анализ приведет к тому, что сетевой трафик станет общедоступным на https://packettotal.com.
        
        चेतावनी: विश्लेषण का परिणाम नेटवर्क ट्रैफिक https://packettotal.com पर सार्वजनिक हो जाएगा
        
        警告：分析将导致网络流量在https://packettotal.com上公开
        
        警告：分析により、ネットワークトラフィックはhttps://packettotal.comで公開されます。
        
        tahdhir: sayuadiy altahlil 'iilaa 'an tusbih harakat murur alshabakat eamat ealaa https://packettotal.com

    """)

    answer = input('Continue? [Y/n]: ')
    if answer.lower() == 'n':
        exit(0)

def print_pt_ascii_logo():
    """
    :return: Prints a PacketTotal.com (visit https://PacketTotal.com!)
    """

    logo = """
                                                           ,,*****,                 ,****,
                                                   ****/**,  /              ,*//*,
                                                   ****/**,  ,,**********,. ******
                            ..  .,*****,  ..       ********  ************,.   .
                    .  .,,***,  ,******, .,***,,..           *****////***,  ,***,
                 ...  ,******,  ,******, .,********          *****////***,. ****,
            .,,****,  ,******,  ,******,  ,********          ************,  .///
             /////* // ////// /( ////// /( */////             ************
    ****,. ,,******.  ,******.  ,******,  .******,,.,******,.               *
    *****, ********,  ,******,  ,******, .,********.,********      ,*******,
    *****, ********,  ,******,  ,******, .,********.,********      ****//**,
    *****, /*******,  ,*******  *//////*  ********/ ,********      ****//**,
    ////* / .////// ((.(((((( ## (((((( (& /(((((  % //////        ,******** .
    ,,,,,. ,,,,,,,,.  ,,*****,  ,******,  ,*****,,,..,,,,,,,. .,,,,,,
    *****, /*******,  *//////*  *//////* .*//////*/.*********,,*****,
    *****, /*******,  *//////*  (.     (  *////////.*********,,******
    *****, /********  */////(* ..,,,,,,..  (/////// ********* *******
    ////* / ,/((((/ #@,####*..,**********,. /####. & /(((((. @ *////
    ,,,,,. ..,,,,*,,  ,**,  ,*****////*****,./***,. ,,,,,,,.. .,,,,,
     ,***, /*****//*  */// .,***//(##((/****, /////,*//******,,***,
     ****, /*****//*  *//* ,****/(%&&%(//**,, ////(,*//******,,****
     ****, /*****//*  *//*  ,***//(##(//***** *///( *//******.***,
      *** ( **///// #@//((. ******////****** /(((* @ //////*   **,
       ,,. ..,,,,,,,  ,****,. ************ .,****,. ,,,,,,,.. ,,*
        *, /********  *//////,   ,****,   ,////////.*********,,*
         * /*******,  *//////*  ,******, .*////////.*********,,
           /********  *//////*  *//////*  *//////*/ *********
            *******,# ////////# ////////#  //////*   /******
             ,,,,,..((.,,,,,,.(#.,,,,,,.(#.,,,,,,..(..,,,,,
            * *****,  ,******,  *//////* .,*******/.,*****
                ***,  ,******,  ,******, .,********.,*** /
               * ,*,  ,******,  ,******,  ,********.,*  .
                      *******/  *******/  ,*******    ,
                       ,,,,,..// .,,,,..// .,,,,,
                      / .****,  ,******, .,****, /
                         / ***  ,******,  ***
                                ********   #
    
                                    - SnappyCap: Capture and analyze network traffic; powered by PacketTotal.com
                                               : VERSION: {}
    """.format(const.VERSION)
    print(logo)

# Setup Logging

mkdir_p('logs/')
mkdir_p('tmp/')
logger = logging.getLogger('snappy_cap.utils')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('logs/snappy_cap.log')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
logger.addHandler(fh)
logger.addHandler(ch)