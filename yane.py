"""
yane.py - Yet Another Nessus Exporter

This program is meant to automate the process of exporting Nessus scans
by accessing the Nessus server and programtically performing the actions
a human user would take to perform the export function.

This program was developed on Kali GNULinux version 2017.1 running Python 3.5.
Testing was performed on:
    1.  Kali GNU/Linux version 2017.1
    2.  Nessus version 6.10.5 (#90)

Python v3.5 modules installed on Kali GNU/Linux

Package             Version
------------------- --------
binwalk             2.1.1
Brlapi              0.6.5
chardet             2.3.0
crcelk              1.1
cryptography        1.7.1
cupshelpers         1.0
cycler              0.10.0
debtags             2.1
decorator           4.0.11
hashID              3.1.4
httplib2            0.9.2
idna                2.2
keyring             10.1
keyrings.alt        1.3
louis               3.0.0
matplotlib          2.0.0
numpy               1.12.1
Pillow              4.0.0
pip                 9.0.1
pyasn1              0.1.9
pycrypto            2.6.1
pycups              1.9.73
pycurl              7.43.0
pygobject           3.22.0
PyOpenGL            3.1.0
pyparsing           2.1.10
pyqtgraph           0.10.
pyserial            3.2.1
pysmbc              1.0.15.6
python-apt          1.4.0b2
python-dateutil     2.5.3
python-debian       0.1.30
python-debianbts    2.6.1
pytz                2016.7
pyxdg               0.25
reportbug           7.1.5
requests            2.12.4
scipy               0.18.1
SecretStorage       2.3.1
setuptools          33.1.1
six                 1.10.0
smoke-zephyr        1.0.2
termineter          0.2
unattended-upgrades 0.1
urllib3             1.19.1
wheel               0.29.0

@author: Ron Reidy (ISYS Technologies)
Copyright(c) Ron Reidy, 2017
    This program is free software and licensed under the GNU
    General Public License (https://www.gnu.org/licenses/gpl.txt).

    You may copy and use this program for your own uses.

    Use of this program is at your own risk.  The author makes no warranties
    as to the use or quality of the program and the company (ISYS Technologies)
    also does not provide any warranty of soundness.

Arguments:

        Mandatory arguments (all required arguments have the string 'required' in
        the help text - see the class method 'ScanExporter._req_args_present'):

        1.  account name - Nessus web site account name (-a or --account-name switch)
        2.  url - the url of the Nessus server (-u or --url switch)
        3.  folder name - name of the folder contaning the scan results (-f or --folder-name switch)
            NOTE: If the folder name has embedded spaces, the folder name must be with quotes.

        Optional arguments:
        1.  scan_startdate - the scan date to download from (-s or --scan-startdate switch)
            NOTE:  If this argument is not present, this program will use
            the current system date minus 1 day.
        2.  scan_enddate - the scan end date to download from (-e or --scan-enddate switch)
            NOTE:  If this argument is not present, this program will use
            the current system date.

usage: python3 yane.py [options] arguments
NOTE:  This program **MUST** be run using Python 3.x or higher.  Using Python 2
       will print an error message and exit.
"""

import os
import re
import sys

"""
must run in Python 3
"""
try:
    REQUIRED_MINIMUM_VERSION = (3, 0)
    current_ver = sys.version_info[:2]

    assert current_ver >= REQUIRED_MINIMUM_VERSION
except AssertionError:
    print >> sys.stderr, "interpreter error: {0} must run in Python v{1:d}.{2:d} or higher (not Python v{3:d}.{4:d})".format(
        sys.argv[0],
        REQUIRED_MINIMUM_VERSION[0],
        REQUIRED_MINIMUM_VERSION[1],
        current_ver[0],
        current_ver[1])
    sys.exit(1)

import csv
import json
import time
import string
import atexit
import urllib
import getpass
import logging
import datetime
import requests

"""
disable InsecureRequestWarning when connecting to the Nessus server using https
"""
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from optparse import OptionParser

"""
global variables
"""
VERIFY                 = False
TOKEN                  = None
URL                    = None
MONTH_DAY_PAD_LEN      = 2
VALID_NESSUS_EXPORTS   = ('nessus', 'csv')
VALID_HTTP_RESOURCES   = ('GET', 'POST', 'DELETE', 'PUT')
__version__ = "1.0"
__program__ = "Yet Another Nessus Exporter (yane) v{0}".format(__version__)
startdt     = datetime.datetime.now()
logger = logging.getLogger(__name__)

"""
make zip files compressed if zlib is installed
"""
import zipfile
COMPRESSION = None
try:
    import zlib
    COMPRESSION = zipfile.ZIP_DEFLATED
except:
    COMPRESSION = zipfile.ZIP_STORED

MODES = {zipfile.ZIP_DEFLATED : 'deflated',
         zipfile.ZIP_STORED   : 'stored'
        }

class NessusRptExc(Exception):
    """
    NessusRptExc - custom exception handler for this program
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

def init_logger(output_dir, logfname):
    """
    init_logger - initialize loggers

    Initializes the program loggin mechanism to log informational
    messages to STDOUT and the log file.

    INFO messages are written to STDOUT as well as the log file.
    All messages written to the log file include the line number where
    the log entry was genetared for debugging purposes.

    The log file is rotated the first day of each month.

    :param output_dir - the directory where the log file will be written
    :param logfname - the prefix of the log file (name of the program without
                      the extension)

    Dependency: global variable logger
    """
    logger.setLevel(logging.DEBUG)

    #   rotate log file on first of month
    this_day = (datetime.date.today().year, datetime.date.today().month)
    logfname += "-{0}{1}.log".format(str(this_day[0]),
                                     str(this_day[1]).zfill(MONTH_DAY_PAD_LEN)
                                    )

    #   create console handler and set level to info
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(filename)s - [%(levelname)s] - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    #   create log file handler and set level to debug
    handler = logging.FileHandler(os.path.join(output_dir, logfname), "a")
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(filename)s:%(lineno)d - [%(levelname)s] - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

def build_http_query(resource):
    """
    build_http_query - create a proper URL for use in the contact() function

    :param resource - the resource (location) to add to the URL

    :return new URL

    Depenency:  global variable URL
    """
    return '{0}{1}'.format(URL, resource)

def connect(method, resource, data=None):
    """
    connect - make a Nessus web connection

    :param method - the HTTP method
    :param resource -
    :param data - the HTTP payload

    :return HTTP page content (when perforn=ming a download)
    :return json data
    """
    if method not in VALID_HTTP_RESOURCES:
        raise ValueError('invalid method: {0}: must be one of {1}'.format(
            method,
            ', '.join(VALID_HTTP_RESOURCES))
        )

    headers = {'X-Cookie': 'token={0}'.format(TOKEN),
               'content-type': 'application/json'
              }

    data = json.dumps(data)

    if method == 'POST':
        r = requests.post(build_http_query(resource),
                          data=data,
                          headers=headers,
                          verify=VERIFY
                         )
    elif method == 'PUT':
        r = requests.put(build_http_query(resource),
                         data=data,
                         headers=headers,
                         verify=VERIFY
                        )
    elif method == 'DELETE':
        r = requests.delete(build_http_query(resource),
                            data=data,
                            headers=headers,
                            verify=VERIFY
                           )
        return
    else:
        r = requests.get(build_http_query(resource),
                         params=data,
                         headers=headers,
                         verify=VERIFY
                        )

    if r.status_code != 200:
        e = r.json()
        raise NessusRptExc(e['error'])

    if 'download' in resource:
        return r.content
    else:
        return r.json()

def connect_web_server(usr, pwd):
    """
    connect_web_server - log into the Nessus web server

    :param usr - the Nessus account name
    :param pwd - the Nessus account password

    :return the HTTP token for a successful login
    """
    login = {'username': usr, 'password': pwd}
    data = connect('POST', '/session', data=login)

    return data['token']

@atexit.register
def logout():
    """
    logout - log out of the Nessus web server

    Dependency: global variables TOKEN, startdt, and __program__
    """
    enddt = datetime.datetime.now()
    if TOKEN is not None:
        connect('DELETE', '/session')

    elapsed = enddt - startdt
    logger.info("end {0} (elapsed time: {1})".format(__program__, elapsed))

def get_scans(folder_name, stdt, endt):
    """
    get_scans - rerieve all scans from all folders

    :param folder_name - the folder name from teh command line options
    :param stdt - the scan start date
    :param endt - the scan end date

    :return scans for teh folder within teh date range
    """
    data = connect('GET', '/scans')

    scans = []
    folder_id = None
    folder_id = find_folder(folder_name, data['folders'])
    if folder_id:
        for scan in data['scans']:
            if scan['folder_id'] == folder_id:
                tmp = datetime.datetime.fromtimestamp(scan['last_modification_date'])
                crdt = tmp.month, tmp.day, tmp.year
                if crdt >= stdt or crdt <= endt:
                    if scan['status'] == 'completed':
                        scans.append(scan)
                    else:
                        logger.warn("scan: {0:d} is not completed: {1}".format(
                            scan['id'],
                            scan['completed'])
                        )
                else:
                    logger.info("scan: {0:d} date {1} is not within the date range".format(
                        scan['id'],
                        '/'.join((str(i).zfill(MONTH_DAY_PAD_LEN) for i in crdt)))
                    )

    return scans, folder_id

def is_nessus_ready(scan_id, file_id):
    """
    is_nessus_ready - is Nessus web server ready to proceed

    :param scan_id - the scan_id under consideration
    :param file_id - the file being downloaded

    :return True (Nessus is ready); False (Nessus is not ready
    """
    data = connect('GET', '/scans/{0}/export/{1}/status'.format(scan_id, file_id))

    return data['status'] == 'ready'

def find_folder(folder_name, folders):
    """
    find_folder - find a folder using the folder name

    :param folder_name - the name of the folder passed on the command line
    :param folders - a list of folders holding all scans

    :return folder_id - the folder ID of the named folder
    """
    folder_id = None
    for folder in folders:
        if folder['name'] == folder_name:
            folder_id = folder['id']
            break

    return folder_id

def export_folder(folder_name, data, zips):
    """
    export_folder - export all reports from the specified folder

    :param folder_name - the name of the folder
    :param data -
    :param zips

    DependencyL global variable VALID_NESSUS_EXPORTS
    """
    scan_cnt = len(data)
    for idx in range(0, scan_cnt):
        for fmt in VALID_NESSUS_EXPORTS:
            logger.info("saving reports to ZIP file: {0}".format(zips[fmt]))
            file_id = export(data[idx]['id'], fmt)
            if file_id is None:
                raise NessusRptExc("unexpected error getting file_id")

            download(data[idx]['name'],
                     data[idx]['id'],
                     file_id,
                     zips[fmt]
                    )

def export(scan_id, fmt):
    """
    export - export the file in the specified format

    :param scan_id - the scan ID
    :param fmt - the download format

    :return file ID of the report to export
    """
    data = {'format': fmt}
    data = connect('POST', '/scans/{0}/export'.format(scan_id), data=data)
    file_id = data['file']
    while not is_nessus_ready(scan_id, file_id):
        time.sleep(2)

    return file_id

def download(report_name, scan_id, file_id, zfname):
    """
    download - download the specified report

    :param report_name - the name of the report
    :param scan_id - the scan ID of the report
    :param file_id - the file ID of the report
    :param save_path - the directory to save scan reports to
    :param zfname - teh ZIP file name to archive the report

    Dependency: global variables MODES and COMPRESSION
    """
    data = connect('GET', '/scans/{0}/export/{1}/download'.format(scan_id,
                                                                  file_id
                                                                 )
                  )

    file_name = re.sub(r'[^\w_.)( -]', '_', '{0}_{1}.nessus'.format(
        report_name,
        file_id)
    )

    logger.info('Saving scan results to {0}'.format(file_name))
    with open(file_name, 'wb') as f:
        f.write(data)

    """
    write the file to teh zipfile
    """
    with zipfile.ZipFile(zfname, 'a') as zf:
        logger.info("adding file: {0} to {1} with compression mode '{2}'".format(
            file_name,
            zfname,
            MODES[COMPRESSION])
        )
        zf.write(file_name, compress_type=COMPRESSION)

    os.unlink(file_name)

    return True

def print_zip_info(zips, folder_name):
    """
    print_zip_info - print a CSV (tab separated values) file of the
                     zip file contents metadata

    :param zips - the ZIP file names
    :param folder_name - the name of the Nessus folder exported

    Dependency: gloabl variable VALID_NESSUS_EXPORTS
    """
    header = ["ZIP File",
              "File name",
              "Comment",
              "Modified date",
              "System",
              "Create version",
              "Compress size (bytes)",
              "File size (bytes)",
             ]
    lines = []

    for zfile in VALID_NESSUS_EXPORTS:
        zname = zips[zfile]
        with zipfile.ZipFile(zname) as zf:
            for info in zf.infolist():
                line = []
                line.append(zips[zfile])
                line.append(info.filename)
                line.append(str(info.comment, 'utf-8'))
                line.append(datetime.datetime(*info.date_time).strftime("%Y-%m-%d %H.%M.%S"))

                if info.create_system == 0:
                    system = 'Windows'
                elif info.create_system == 3:
                    system = 'UNIX'
                else:
                    system = 'UNKNOWN'

                line.append(system)
                line.append(info.create_version)
                line.append(info.compress_size)
                line.append(info.file_size)

                lines.append(line)

    if len(lines):
        cname = "nessus_scan_export-{0}-{1}{2:02d}{3:02d}-{4:02d}.{5:02d}.{6:02d}.csv".format(
            folder_name,
            startdt.year,
            startdt.month,
            startdt.day,
            startdt.hour,
            startdt.minute,
            startdt.second)

        logger.info("saving ZIP file information to {0} (tab seprated file)".format(cname))
        with open(cname, 'w', newline='') as f:
            wrtr = csv.writer(f, quoting=csv.QUOTE_ALL, delimiter='\t')
            wrtr.writerow(header)
            wrtr.writerows(lines)

def req_args_present(opt, parser):
    """
    req_args_present - ensure required arguments are present

    :param opt: command line options Namespace object
    :param parser: the parser opject
    :return an array of missing arguments
    """
    missing = []
    for option in parser.option_list:
        if 'required' in option.help and eval('opt.' + option.dest) is None:
            missing.extend(option._long_opts)

    return missing

def validate_url(url):
    """
    validate_url - validate the URL is properly formatted

    :param url: the URL passed on the command line
    :return None if the URL is not in the proper format (http[s]://server:port)
    :return the URL if valid
    """
    if url.endswith('/'):
        logger.info("removed trailing '/' from url")
        url = url[:-1]

    (scheme, netloc) = urllib.parse.urlparse(url)[:2]
    if not re.search(r'\w+:\d+$', netloc):
        return None

    return url

def check_scan_dts(sdt, edt):
    """
    check_scan_dts - validate (or create) scan dates

    :param sdt - start date
    :param edt - end date

    :return stdt - start date (tuple of date - month, day, year) and
            enddt - end date (tuple of month, day, year)

    :raises date error: start date is greater than the system date
    :raises date error: the end date is before the start date

    Dependency: global variable startdt
    """
    sys_dt = startdt.month, startdt.day, startdt.year
    stdt   = None
    enddt  = None

    if sdt is None:
        stdt = startdt - datetime.timedelta(days=1)
    else:
        stdt = datetime.datetime.strptime(sdt, '%m/%d/%Y')

        if stdt > startdt:
            raise ValueError("date error: {0} is greater than the system date {1}".format(
                    sdt,
                    '/'.join((str(i).zfill(MONTH_DAY_PAD_LEN) for i in sys_dt)))
            )

    if edt is None:
        enddt = startdt
    else:
        enddt = datetime.datetime.strptime(edt, '%m/%d/%Y')

    days = abs(stdt - enddt)

    stdt = stdt.month, stdt.day, stdt.year
    enddt = enddt.month, enddt.day, enddt.year

    if enddt < stdt:
        raise ValueError("date error: the end date {0} is before the start date {1}".format(
            '/'.join((str(i).zfill(MONTH_DAY_PAD_LEN) for i in enddt)),
            '/'.join((str(i).zfill(MONTH_DAY_PAD_LEN) for i in stdt))
        ))

    logger.info("exporting scans between {0} and {1} ({2:d} day(s))".format(
        '/'.join((str(i).zfill(MONTH_DAY_PAD_LEN) for i in stdt)),
       '/'.join((str(i).zfill(MONTH_DAY_PAD_LEN) for i in enddt)),
        days.days
    ))

    return stdt, enddt

def mk_zips(folder_name):
    """
    mk_zips - make ZIP file names
    :return dictionary of ZIP file names (NESSUS and CSV)

    Dependency: global variable VALID_NESSUS_EXPORTS
    """
    zips = {}
    for rpt in VALID_NESSUS_EXPORTS:
        zips[rpt] = "{0}_{1}{2}{3}-{4}_{5}_{6}-{7}.zip".format(
            folder_name,
            startdt.year,
            str(startdt.month).zfill(MONTH_DAY_PAD_LEN),
            str(startdt.day).zfill(MONTH_DAY_PAD_LEN),
            str(startdt.hour).zfill(MONTH_DAY_PAD_LEN),
            str(startdt.minute).zfill(MONTH_DAY_PAD_LEN),
            str(startdt.second).zfill(MONTH_DAY_PAD_LEN),
            rpt)

    return zips

if __name__ == "__main__":
    init_logger(os.path.dirname(os.path.realpath(__file__)),
                __file__.split('.')[0]
               )

    logger.info("starting {0}".format(__program__))
    rc = 0
    try:
        parser = OptionParser(usage="usage: %prog [options] arguments",
                          description="Nessus scan exporter",
                          version=__version__
                         )
        parser.add_option('-a', '--account-name',
                          action   = 'store',
                          dest     = 'uid',
                          help     = 'Nessus account name to use for downloading scans - required'
                         )
        parser.add_option('-u', '--url',
                          action   = 'store',
                          dest     = 'url',
                          help     = 'Nessus web site URL and port (e.g. "https://127.0.0.1:8834") - required'
                         )
        parser.add_option('-f', '--folder-name',
                          action   = 'store',
                          dest     = 'folder_name',
                          help     = 'Nessus folder to download scans from - required'
                         )
        parser.add_option('-s', '--scan-startdate',
                          action   = 'store',
                          dest     = 'scan_startdate',
                          help     = 'Start date of nessus scans (format: mm/dd/yyyy); will default to system date minus 1 day'
                         )
        parser.add_option('-e', '--scan_enddate',
                          action  = 'store',
                          dest    = 'scan_enddate',
                          help    = 'End date of Nessus scans (format: mm/dd/yyyy) will default to system date',
                         )

        opt, _ = parser.parse_args()
        missing_args = req_args_present(opt, parser)
        if len(missing_args) > 0:
            raise NessusRptExc("Missing REQUIRED arguments: {0}".format(', '.join(missing_args)))

        URL = validate_url(opt.url)
        if URL is None:
            raise NessusRptExc("invalid URL: {0} - format is http[s]://server:port".format(opt.url))

        opt.scan_startdate, opt.scan_enddate = check_scan_dts(opt.scan_startdate, opt.scan_enddate)
        zips = mk_zips(opt.folder_name)
        password = getpass.getpass('Enter the passsword for Nessus account {0}: '.format(opt.uid))
        if password is None or len(password.rstrip("\n")) == 0:
            raise ValueError("password is required")

        TOKEN = connect_web_server(opt.uid, password)
        logger.info("connected to {0} as {1}".format(opt.url, opt.uid))

        scan_data, folder_id = get_scans(opt.folder_name,
                                         opt.scan_startdate,
                                         opt.scan_enddate
                                        )
        if folder_id is None:
            raise ValueError("folder: {0} not found".format(opt.folder_name))

        if len(scan_data) == 0:
            raise ValueError("data not found: no scans found for folder: {0} within the date range of {1} and {2}".format(
                opt.folder_name,
                '/'.join((str(i).zfill(MONTH_DAY_PAD_LEN) for i in opt.scan_startdate)),
                '/'.join((str(i).zfill(MONTH_DAY_PAD_LEN) for i in opt.scan_enddate)))
            )

        export_folder(opt.folder_name, scan_data, zips)
        print_zip_info(zips, opt.folder_name)

    except ValueError as e:
        logger.error(e)
        rc += 1
    except AssertionError as e:
        logger.error(e)
        rc += 1
    except NessusRptExc as e:
        logger.error(e)
        parser.print_help(file=sys.stderr)
        rc += 1
    except Exception as e:
        logger.error(e)
        rc += 1
    finally:
        sys.exit(rc)

