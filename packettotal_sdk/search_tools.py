import time
import typing
import requests
from sys import stderr
from datetime import datetime


from packettotal_sdk import packettotal_api


class SearchTools(packettotal_api.PacketTotalApi):

    def __init__(self, api_key: str):
        """
        :param api_key: An API authentication token
        """
        super().__init__(api_key)

    def search_by_pcap(self, pcap_file_obj: typing.BinaryIO) -> requests.Response:
        """
        Search by a pcap/pcapng file, get list list of similar packet captures

        :param pcap_file_obj: A file like object that provides a .read() interface (E.G open('path_to_pcap.pcap, 'rb') )
        :return: A request.Response instance, containing a graph of similar pcaps with matched terms
        """
        response = super().analyze(pcap_file_obj)
        if response.status_code == 200:
            sim_response = super().pcap_similar(response.json()['pcap_metadata']['md5'])
        elif response.status_code == 202:
            pcap_id = response.json()['id']
            info_response = super().pcap_info(pcap_id)
            while info_response.status_code == 404:
                print('[{}] Waiting for {} to finish analyzing.'.format(datetime.utcnow(), pcap_id))
                info_response = super().pcap_info(response.json()['id'])
                time.sleep(10)
            print('[{}] Fetching results for {}.'.format(datetime.utcnow(), pcap_id))
            time.sleep(5)
            sim_response = super().pcap_similar(response.json()['id'])
        else:
            return response
        return sim_response

    def search_by_iocs(self, ioc_file: typing.TextIO) -> requests.Response:
        """
        Search up to 100 IOC terms at once, and get matching packet captures

        :param ioc_file: A file like object that provides a .read() interface (E.G open('path_to_iocs.txt, 'r')
                         contents are line delim
        :return: A request.Response instance containing the search results containing at least one matching IOC
        """
        text = ioc_file.read()
        delim = '\n'
        if '\r\n' in text[0:2048]:
            delim = '\r\n'
        elif '\r' in text[0:2048]:
            delim = '\r'
        elif ',' in text[0:2048]:
            delim = ','
        elif '\t' in text[0:2048]:
            delim = '\t'
        text_delimd = text.split(delim)
        search_str = ''
        for i, ioc in enumerate(text_delimd[0: -2]):
            search_str += '"{}" OR '.format(ioc.strip())
            if i > 100:
                print('Warning searching only the first 100 IOC terms of {}.'.format(len(text_delimd)), file=stderr)
                break
        search_str += '"{}"'.format(text_delimd[-1].strip())
        response = super().search(search_str)
        return response
