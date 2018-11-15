import os
import sys
import csv
import logging
import sqlite3
import warnings
from time import sleep
from datetime import datetime


import boto3
import botocore
import progressbar
import requests
import terminaltables
from IPy import IP


from snappycap.lib import const
from snappycap.lib.utils import listen_on_interface
from snappycap.lib.utils import capture_on_interface
from snappycap.lib.utils import get_filepath_md5_hash

logger = logging.getLogger('snappy_cap.interfaces')
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


class Capture:
    """
    Provides the ability to capture, upload, and save packet captures
    """

    def __init__(self, interface='lo', timeout=60, filepath=None):
        self.interface = interface
        self.timeout = timeout
        self.path = filepath
        self.capture_start = None
        self.capture_end = None
        self.upload_start = None
        self.upload_end = None
        self.md5 = None
        self.size = None
        self.name = 's_cap_' + \
                    str(datetime.now()).replace('-', '').replace('.', '').replace(':', '').replace(' ', '') + '.pcap'
        if self.path and os.path.isfile(str(self.path)):
            self.size = os.path.getsize(self.path)
            self.md5 = get_filepath_md5_hash(self.path)
            self.name = os.path.basename(self.path)

    def capture(self):
        """
        Begin a packet capture
        """

        try:
            logger.info("Beginning packet capture for {} seconds.".format(self.timeout))
            self.capture_start = datetime.utcnow()
            self.size = capture_on_interface(self.interface, self.name, timeout=self.timeout)
            self.capture_end = datetime.utcnow()
            self.md5 = get_filepath_md5_hash('tmp/{}'.format(self.name))
            self.path = 'tmp/{}'.format(self.name)
        except Exception as e:
            logger.error("An error was encountered while capturing on {} - {}".format(self.interface, e), exc_info=True)

    def upload(self):
        """
        Begin an upload to public bucket
        """

        if self.size == 0:
            logger.error("Will not upload PCAP of 0 bytes. {} ({})".format(self.md5, self.name))
            return
        try:
            logger.info("Beginning upload to public repo {}".format(self.path))
            self.upload_start = datetime.utcnow()
            session = boto3.Session(
                aws_access_key_id=const.PUBLIC_USER,
                aws_secret_access_key=const.PUBLIC_KEY
            )
            s3 = session.resource('s3')
            bucket = s3.Bucket('snappycap')
            bucket.put_object(
                Key=self.name,
                Body=open(self.path, 'rb'),
            )
            self.upload_end = datetime.utcnow()
        except botocore.exceptions.ClientError as e:
            logger.error('You have not been whitelisted to upload to this repository. White-list your IP by filling '
                         'out the form here - https://goo.gl/forms/P0Io8NqPAfM42EWJ2')
            raise e
        except Exception as e:
            logger.error("Failed to complete S3 upload for {} - {}".format(self.name, e), exc_info=True)
            raise e

    def save(self):
        """
        Save the submission for analysis later
        """

        try:
            Database().insert_pcap([
                self.md5,
                self.name,
                self.capture_start,
                self.capture_end,
                self.upload_start,
                self.upload_end,
                self.size
            ])
            return True
        except Exception as e:
            if 'UNIQUE' in str(e):
                logger.warning('Skipping save, we\'ve analyzed this pcap before: {} ({}).'.format(self.md5,
                                                                                    self.name))
            else:
                logger.error("Failed to complete database write of {} ({}) - {}".format(self.md5,
                                                                                    self.name, e), exc_info=True)
            return False

    def cleanup(self):
        """
        Remove the temporary file from your tmp directory
        """

        os.remove('tmp/{}'.format(self.name))


class Database:
    """
    Provides a basic CRUD interface for storing submission metadata
    """

    def __init__(self):
        self.conn = sqlite3.connect('database.db')

    def initialize_database(self):
        """
        Creates a new database instance and default pcaps table (if one does not already exist)
        """
        c = self.conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS pcaps (
                    id VARCHAR(32) PRIMARY KEY,
                    name VARCHAR(50),
                    capture_start TEXT,
                    capture_end TEXT,
                    upload_start TEXT,
                    upload_end TEXT,
                    size INTEGER);
                  ''')

        c.execute('''CREATE TABLE IF NOT EXISTS completed (
                    id VARCHAR(32) PRIMARY KEY,
                    data TEXT,
                    FOREIGN KEY(id) REFERENCES pcaps(id)
                    );
                  ''')
        self.conn.commit()

    def insert_pcap(self, row):
        """
        :param row: A list containing all the items of a completed analysis
                    [id, name, capture_start, capture_end, upload_start, upload_end, size]
        """

        c = self.conn.cursor()
        c.execute('''INSERT INTO pcaps(id, name, capture_start, capture_end, upload_start, upload_end, size)  
        VALUES(?,?,?,?,?,?,?);''', row)
        self.conn.commit()


    def insert_completed(self, row):
        c = self.conn.cursor()
        c.execute('''INSERT INTO completed(id, data) 
        VALUES(?,?);''', row)
        self.conn.commit()


    def select_pcaps(self):
        c = self.conn.cursor()
        try:
            res = c.execute('SELECT * FROM pcaps;')
        except Exception:
            logger.info('No PCAPs analyzed yet. Submit your first pcap before using this option.')
            exit(0)
        return res

    def select_completed(self, _id):
        c = self.conn.cursor()
        res = c.execute("SELECT * FROM completed WHERE id='{}';".format(_id))
        return res

class PTClient:
    """
    Provides a simple interface for retrieving information about a submission
    """

    def __init__(self):
        self.base = "https://packettotal.com"
        self.useragent = 'SnappyCap Client Version {}'.format(const.VERSION)
        self.session = requests.session()



    def get_pcap_status(self, _id):
        """
        :param _id: The md5 has associated with the pcap file
        :return: a submission object if found, None otherwise
        """
        url = self.base + '/app/submission/status?id={}'.format(_id)
        res = requests.get(url, headers={
            'User-Agent': self.useragent,
            'Accept': 'text/json'
        })
        suc, data = res.json()
        if suc:
            return data
        return None


def export_submissions_status():
    """
    #Exports the results (analysis statuses) of all submissions to a csv
    """
    with open('pcap-statuses.csv', 'w') as f:
        writer = csv.writer(f, dialect='excel')
        table = [['Capture MD5',
                  'Capture Name',
                  'Capture Start',
                  'Capture End',
                  'Upload Start',
                  'Upload End',
                  'Size',
                  'Queued',
                  'Analysis Started',
                  'Analysis Completed',
                  'Malicious',
                  'Link']]
        table.extend(get_submissions_status())
        print('\n=== Written to {} ==='.format('pcap-statuses.csv'))
        writer.writerows(table)


def get_submissions_status():
    """
    :return: A list of statuses of all the submissions in the database
    """
    results = []
    database = Database()
    print("Fetching analysis statuses...Please wait.")
    for row in progressbar.progressbar(Database().select_pcaps()):
        _id, name, capture_start, capture_end, upload_start, upload_end, size = row
        print(next(database.select_completed(_id)))
        res = PTClient().get_pcap_status(_id)
        database.insert_completed([_id, str(res)])
        queued, analysis_started, analysis_completed = False, False, False
        link = None
        malicious = None
        if res:
            submission = res.get('submission', {})
            if submission.get('queuedTimestamp'):
                queued = True
            if submission.get('analysisStarted'):
                analysis_started = True
            if submission.get('analysisCompleted'):
                analysis_completed = True
                if 'signature_alerts' in submission.get('logsTransmitted'):
                    malicious = True
                else:
                    malicious = False
        if analysis_completed:
            link = "https://packettotal.com/app/analysis?id={}".format(_id)
        results.append([_id, name, capture_start, capture_end, upload_start, upload_end, size, queued, analysis_started,
                        analysis_completed, malicious, link])
    return results


def print_submission_status():
    """
    Prints a formatted table of submitted PCAPs
    """
    table = [['Capture MD5',
              'Capture Name',
              'Capture Start',
              'Capture End',
              'Upload Start',
              'Upload End',
              'Size',
              'Queued',
              'Analysis Started',
              'Analysis Completed',
              'Malicious',
              'Link']]
    table.extend(get_submissions_status())
    print(terminaltables.AsciiTable(table).table)


class Trigger:

    def __init__(self, interface, capture_period_after_trigger=60):
        self.interface = interface
        self.capture_period_after_trigger = capture_period_after_trigger
        self.whitelisted_ips = []
        self._open_whitelist()


    def _open_whitelist(self):
        try:
            with open('ip.whitelist', 'r') as f:
                self.whitelisted_ips = [line.strip() for line in f.readlines() if line.strip() != '']
        except FileNotFoundError:
            self.whitelisted_ips = []


    def learn(self, timeout=60):
        src_ips = set()
        dst_ips = set()

        with open('ip.whitelist', 'w') as f:
            if not sys.warnoptions:
                warnings.simplefilter("ignore")
            print('Generating whitelist of IP addresses based on traffic from the next {} seconds.'.format(timeout))
            bar = progressbar.ProgressBar(max_value=progressbar.UnknownLength)
            for conn in self.listener(timeout=timeout):
                try:
                    src, dst, proto = conn
                    if IP(src).iptype() == 'PUBLIC':
                        src_ips.add(src)
                        bar.update(len(src_ips) + len(dst_ips))
                    if IP(dst).iptype() == 'PUBLIC':
                        dst_ips.add(dst)
                        bar.update(len(src_ips) + len(dst_ips))
                except AttributeError:
                    pass
            all_ips = list(src_ips)
            all_ips.extend(dst_ips)
            all_ips = set(all_ips)
            for ip in all_ips:
                f.write(ip + '\n')


    def listener(self, timeout=None):
        for packet in listen_on_interface(interface=self.interface, timeout=timeout):
            try:
                yield packet.ip.src, packet.ip.dst, packet.transport_layer
            except AttributeError:
                continue


    def listen_and_trigger(self):
        suppress = None # We don't want to trigger on the same IP twice in a row
        while True:
            for conn in self.listener(timeout=None):
                src, dst, _ = conn
                trigger = None
                if src not in self.whitelisted_ips:
                    if src == suppress:
                        break
                    if IP(src).iptype() == 'PUBLIC':
                        logger.info("Trigger [Source: {} not in whitelist] Capturing for {} seconds"
                                     .format(src, self.capture_period_after_trigger))
                        trigger = src
                elif dst not in self.whitelisted_ips:
                    if dst == suppress:
                        break
                    if IP(dst).iptype() == 'PUBLIC':
                        logger.info("Trigger [Destination {} not in whitelist] Capturing for {} seconds"
                                     .format(src, self.capture_period_after_trigger))
                        trigger = dst
                if trigger:
                    capture = Capture(self.interface, timeout=self.capture_period_after_trigger)
                    capture.capture()
                    suppress = trigger
                    try:
                        if capture.save():
                            capture.upload()
                            logger.info('Upload complete')
                    except Exception:
                        logger.error('Upload Failed')
                    # We don't want to upload packets that we already captured (and analyzed),
                    # so we break out of this inner loop
                    break
            # We don't want to trigger on S3 upload, buffer tends to be a bit backed up
            sleep(30)