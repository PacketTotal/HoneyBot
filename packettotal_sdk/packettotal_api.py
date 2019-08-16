import os
import json
import typing
import base64
import requests

PT_API_BASE = os.environ.get('PACKETTOTAL_API_BASE_URL')
PT_API_VERSION_STRING = os.environ.get('PACKETTOTAL_API_VERSION_STRING')


class PacketTotalApi:
    """
    Client that provides search/analysis capabilities

    Sign up here: https://www.packettotal.com/api.html
    """

    def __init__(self, api_key: str):
        """
        :param api_key: An API authentication token
        """
        self.headers = {
            'x-api-key': api_key
        }
        self.base_url = 'https://api.packettotal.com/'
        self.version = 'v1'
        if PT_API_BASE:
            self.base_url = PT_API_BASE
        if PT_API_VERSION_STRING:
            self.version = PT_API_VERSION_STRING

    def analyze(self, pcap_file_obj: typing.BinaryIO, pcap_name=None, pcap_sources=None) -> requests.Response:
        """
        Publicly analyze a PCAP file

        :param pcap_file_obj: A file like object that provides a .read() interface (E.G open('path_to_pcap.pcap, 'rb') )
        :param pcap_name: The optional name of the pcap file, if none is given the md5 hash of the PCAP is used
        :param pcap_sources: The optional list of URLs referencing making reference to the PCAP file
        :return: A request.Response instance, containing information such as where the finished analysis can be found
        """
        pcap_base64 = base64.b64encode(pcap_file_obj.read())
        pcap_base64 = pcap_base64.decode('utf-8')

        self.headers['Content-Type'] = 'application/json'
        body = {
            'pcap_base64': pcap_base64
        }

        if pcap_name:
            body['pcap_name'] = pcap_name

        if isinstance(pcap_sources, list):
            body['sources'] = pcap_sources

        response = requests.post(
            self.base_url + self.version + '/analyze/base64',
            headers=self.headers,
            data=json.dumps(body)
        )
        return response

    def search(self, query: str, pretty=False) -> requests.Response:
        """
        Search with term or with a valid Lucene query.
        https://www.packettotal.com/api-docs/#/search/get_search

        :param query: A search term, such as an IP address or file hash.
        :param pretty: True, if you wish the response.text to be human readable
        :return: A request.Response instance, containing the results of the search query
        """
        pretty_str = '&pretty={}'.format(str(pretty).lower())
        response = requests.get(
            self.base_url + self.version + '/search?query={0}{1}"'.format(query, pretty_str),
            headers=self.headers
        )

        return response

    def deep_search_create(self, query: str) -> requests.Response:
        """
        Create a new deep search task. Search for a term or with a Lucene query.
        Deep searches run longer and can return more results than a normal search.
        The are executed asyncronously, and results must be fetched later using the resulting search_id
        https://www.packettotal.com/api-docs/#/search/post_search_deep

        :param query: A search term, such as an IP address or file hash.
        :return: A request.Response instance, containing the corresponding search_id, which can be used to retrieve
        results at a later point
        """
        body = {
            'query': query
        }
        response = requests.post(
            self.base_url + self.version + '/search/deep',
            headers=self.headers,
            data=json.dumps(body)
        )

        return response

    def deep_search_get(self, search_id: str, pretty=False) -> requests.Response:
        """
        Get the results from a deep search task.
        https://www.packettotal.com/api-docs/#/search/get_search_deep_results__search_id_

        :param search_id: An id corresponding to the search you previously created.
        :param pretty: True, if you wish the response.text to be human readable
        :return: A request.Response instance, containing the results of the initial deep search query
        """
        pretty_str = '?pretty={}'.format(str(pretty).lower())
        response = requests.get(
            self.base_url + self.version + '/search/deep/results/{0}{1}'.format(search_id, pretty_str),
            headers=self.headers
        )

        return response

    def pcap_analysis(self, pcap_md5: str) -> requests.Response:
        """
        Get a detailed report of PCAP traffic, carved files, signatures, and top-talkers.
        https://www.packettotal.com/api-docs/#/pcaps/get_pcaps__pcap_id__analysis

        :param pcap_md5: An md5 hash corresponding to the PCAP file submission on PacketTotal.com
        :return: A request.Response instance, containing more detailed information about the contents of a PCAP file
        """
        response = requests.get(
            self.base_url + self.version + '/pcaps/{0}/analysis'.format(pcap_md5),
            headers=self.headers
        )

        return response

    def pcap_download(self, pcap_md5: str) -> requests.Response:
        """
        Download a PCAP analysis archive. The result is a zip archive containing the PCAP itself, CSVs representing
        various analysis results, and all carved files.
        https://www.packettotal.com/api-docs/#/pcaps/get_pcaps__pcap_id__download

        :param pcap_md5: An md5 hash corresponding to the PCAP file submission on PacketTotal.com
        :return: A request.Response instance, containing the download zip archive
        """
        response = requests.get(
            self.base_url + self.version + '/pcaps/{0}/download'.format(pcap_md5),
            headers=self.headers
        )

        return response

    def pcap_info(self, pcap_md5: str) -> requests.Response:
        """
        Get high-level information about a specific PCAP file.
        https://www.packettotal.com/api-docs/#/pcaps/get_pcaps__pcap_id_

        :param pcap_md5: An md5 hash corresponding to the PCAP file submission on PacketTotal.com
        :return: A request.Response instance, containing high-level metadata about a PCAP submission
        """
        response = requests.get(
            self.base_url + self.version + '/pcaps/{0}'.format(pcap_md5),
            headers=self.headers
        )

        return response

    def pcap_similar(self, pcap_md5: str, intensity='low', weighting_mode='behavior',
                     prioritize_uncommon_fields=False, pretty=False) -> requests.Response:
        """
        Get a similarity graph relative to the current PCAP file.
        https://www.packettotal.com/api-docs/#/pcaps/get_pcaps__pcap_id__similar

        :param pcap_md5: An md5 hash corresponding to the PCAP file submission on PacketTotal.com
        :param intensity: [minimal|low|medium|high] The scope of the search, basically translates to the maximum number
        of aggregations to exhaust.
        :param weighting_mode: [behavior|content] Weight search results either based on their similarity to the
        behaviors exhibited or contents contained within the current PCAP file.
        :param prioritize_uncommon_fields: By default, the most common values are used to seed the initial similarity
        search. Enabling this parameter, seeds the initial search with the least common values instead.
        :param pretty: True, if you wish the response.text to be human readable
        :return: A request.Response instance, containing a graph of similar pcaps with matched terms
        """
        intensity_str = '?intensity={}'.format(intensity)
        weighting_mode_str = '&weighting_mode={}'.format(weighting_mode)
        prioritize_uncommon_fields_str = '&prioritize_uncommon_fields={}'.format(
            str(prioritize_uncommon_fields).lower())
        pretty_str = '&pretty={}'.format(str(pretty).lower())

        response = requests.get(
            self.base_url + self.version + '/pcaps/{0}/similar{1}{2}{3}{4}'.format(
                pcap_md5, intensity_str, weighting_mode_str, prioritize_uncommon_fields_str, pretty_str),
            headers=self.headers
        )

        return response

    def usage(self) -> requests.Response:
        """
        Retrieve API usage and subscription plan information.
        https://www.packettotal.com/api-docs/#/usage/get_usage

        :return: A request.Response instance, containing information about requests made, and your current subscription
        """
        response = requests.get(
            self.base_url + self.version + '/usage',
            headers=self.headers
        )

        return response

    def set_version(self, version: str) -> None:
        """
        Set the API version

        :param version: The version prefix for the API (E.G v1)
        """
        self.version = version

    def set_api_key(self, api_key) -> None:
        """
        Set the API key

        :param api_key: An API authentication token
        """
        self.headers = {
            'x-api-key': api_key
        }
