#!/usr/local/bin/python3

"""
    nasl_cfg_rpt.py - gather NASL file configuration data
    
    usage: python3 nasl_cfg_rpt.py [-h] -p|--path path_to_nasl_files
    
    @author: Ron Reidy
    
    @created: May 5, 2017
    
"""

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
    _ = print >> sys.stderr, "interpreter error: {0} must run in Python v{1:d}.{2:d} or higher (not Python v{3:d}.{4:d})".format(
            sys.argv[0],
            REQUIRED_MINIMUM_VERSION[0],
            REQUIRED_MINIMUM_VERSION[1],
            current_ver[0],
            current_ver[1])

    sys.exit(1)

import csv
import glob
import os.path
from optparse import OptionParser

from collections import OrderedDict

class GatherNASLConfig():
    """
    regex to parse NASL script lines looking for the configuration items
    
    The tags of interest are:
    
     1.  script_id
     2.  script_family
     3.  script_version
     4.  script_cvs_date
     5.  script_osvdb_id
     6.  script_bugtrack_id
     7.  script_cve_id
     8.  script_name
     9.  script_summary
    10.  script_copyright
    """
    CFG_RE = re.compile(
        r"""
        ^\s*
        (?P<item>script_(id|family|version|cvs_date|osvdb_id|bugtraq_id|cve_id|name|summary|copyright))
        \s*\((?P<data>.*)\)
        """
    )
    
    def __init__(self):
        """
        This class instantiates an OrderedDict type
        
        The ordering of output is the order of the dictionary keys in the class
        """
        self.COMPONENT_RE = OrderedDict()
        
        self.COMPONENT_RE['script_family']     = re.compile(r"\w+:\s*\"(?P<config>.*)\"")
        self.COMPONENT_RE['script_id']         = re.compile(r"(?P<config>\d+)")
        self.COMPONENT_RE['script_cvs_date']   = re.compile(r"\"\$Date:\s*(?P<config>.*)\s*\$\"")
        self.COMPONENT_RE['script_cve_id']     = re.compile(r"\"(?P<config>.*)\"")
        self.COMPONENT_RE['script_bugtraq_id'] = re.compile(r'(?P<config>.*)')
        self.COMPONENT_RE['script_osvdb_id']   = re.compile(r"(?P<config>\d+)")
        self.COMPONENT_RE['script_version']    = re.compile(r"\"\$Revision:\s*(?P<config>\d*\.\d*)\s*\$\"")
        self.COMPONENT_RE['script_name']       = re.compile(r"\w+:\s*\"(?P<config>.*)\"")
        self.COMPONENT_RE[ 'script_summary']   = re.compile(r"\w+:\s*\"(?P<config>.*)\"")
        self.COMPONENT_RE['script_copyright']  = re.compile(r"\w+:\s*\"(?P<config>.*)\"")
        
        self.all_keys = self.COMPONENT_RE.keys()
    
    def parse(self, fname):
        """
        parse - read and parse NASL file lines
        """
        
        cfg_data = {}
        
        with open(fname, "r") as fp:
            for fline in fp.readlines():
                if fline.startswith('#') or len(fline.rstrip("\n")) == 0:
                    continue
                
                mtch = self.CFG_RE.match(fline)
                if mtch:
                    item = mtch.group('item')
                    mdata = mtch.group('data')
                    if item in self.all_keys:
                        comp_mtch = self.COMPONENT_RE[item].match(mdata)
                        if comp_mtch:
                            if item in 'script_bugtraq_id':
                                cfg_data[item] = comp_mtch.group('config').replace(", ", "|")
                            else:
                                cfg_data[item] = comp_mtch.group('config')
        
        return cfg_data

def req_args_present(opt, argparser):
    """
    req_args_present - ensure required arguments are present

    :param opt: command line options Namespace object
    :param parser: the parser opject
    :return an array of missing arguments
    """
    missing = []
    for option in argparser.option_list:
        if 'required' in option.help and eval('opt.' + option.dest) is None:
            missing.extend(option._long_opts)

    return missing

if __name__ == "__main__":
    parser = OptionParser(description="NASL script configuration report program")
    parser.add_option('-p', '--path',
                      action   = 'store',
                      dest     = 'path',
                      help     = "path to .nasl files - required"
                     )
    parser.add_option('-c', '--csv-name',
                      action   = 'store',
                      dest     = 'csvfname',
                      help     = "output CSV file name - required"
                     )
    
    rc = 0
    try:
        opt, _ = parser.parse_args()
        missing_args = req_args_present(opt, parser)
        if len(missing_args) > 0:
            raise ValueError("Missing REQUIRED arguments: {0}".format(', '.join(missing_args)))
        
        cfg = GatherNASLConfig()
        with open(opt.csvfname, "wt") as f:
            csvwrtr = csv.writer(f)
            csvwrtr.writerow(cfg.all_keys)
            for nasl in glob.glob(os.path.join(opt.path, "*.nasl")):
                data = cfg.parse(nasl)
                if data:
                    line = []
                    line.append(nasl)
                    for k in cfg.all_keys:
                        if k in data:
                            line.append(data[k])
                    
                    csvwrtr.writerow(line)
    except Exception as e:
        print(e, file=sys.stderr)
        rc += 1
    finally:
        sys.exit(rc)
        