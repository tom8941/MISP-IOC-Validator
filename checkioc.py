#!/usr/bin/env python
# -*- coding: utf-8 -*-

# MISP-IOC-Validator - Validate IOC from MISP ; Export results and iocs to SIEM and sensors using syslog and CEF format
#
# Copyright (C) 2016 Thomas Hilt
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
from netaddr import IPNetwork, IPAddress
import argparse
import os
import os.path
import json
import time
import socket
from datetime import timedelta, date, datetime
from shutil import copyfile
from cybox.objects.file_object import File
import stix.utils as utils
from stix.core import STIXPackage, STIXHeader
from stix.indicator import Indicator
import dumbpig
from cef import *
from ioctest import *
from dataload import *
import time
import smtplib
import sys
import csv
import re

from email.mime.text import MIMEText

#import requests
#from requests.packages.urllib3.exceptions import InsecureRequestWarning
#requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

MAIL_FROM = 'localhost@localhost.local'
MAIL_SERVER = 'smtp.localhost.local'

yara_processed = set()
snort_processed = set()
mailed_attributes = set()

stix_supported = set(['filename|sha1','sha1','filename|md5','md5','filename|sha256','sha256'])
stix_indicators = set()

def _get_misp_version(misp):
    '''Return the version of misp from the misp instance given.

    misp -- misp instance connected.
    '''
    misp_version = json.dumps(misp.get_version()).encode('utf8').decode('string_escape')
    misp_version = misp_version[1::] # remove first "
    misp_version = misp_version[:-1] # remove last "
    misp_version = misp_version.split(':')[1]
    misp_version = misp_version.strip(' ')
    misp_version = misp_version.strip('"')

    return misp_version

def _perdelta(start, end, delta):
    '''Generates and yields dates between start and end with a gap of days between dates defined by delta.

    start -- start date of the range.
    end -- end date of the range.
    delta -- day gap number between dates to yield.
    '''
    curr = start
    while curr < end:
        yield curr
        curr += delta

def _create_date_list(start, end, delta):
    '''Returns a list of the dates between start and end with a gap of days between dates defined by delta.

    start -- start date of the range.
    end -- end date of the range.
    delta -- day gap number between dates to return.
    '''
    dates=start.split('-')
    start_date = date(int(dates[0]), int(dates[1]), int(dates[2]))

    datee=end.split('-')
    end_date = date(int(datee[0]), int(datee[1]), int(datee[2]))

    rangesize = int(delta)

    datelist = [str(result) for result in _perdelta(start_date,end_date,timedelta(days=rangesize))]
    datelist.append(str(end_date)) # add border date

    return datelist

def _get_stix_indicator(ioc, uuid, stix_file):
    '''Add one ioc to a stix indicator and return the indicator object

    ioc -- contains the ioc value
    uuid -- uuid of the ioc (attribute uuid)
    stix_file -- stix file to write
    '''

    if '|' in ioc: # like in filename|md5
        ioc = ioc.split('|')[1]

    f = File()

    indicator = Indicator()
    indicator.title = uuid
    indicator.description = ("ioc with MISP attribute id : " + uuid)
    indicator.set_producer_identity("checkioc of tom8941")
    indicator.set_produced_time(utils.dates.now())

    f.add_hash(ioc)
    indicator.add_object(f)

    return indicator

def _export_yara(yara_rule,yara_file,yara_except_set):
    '''Write yara_rule in yara_file

    yara_rule -- Yara rule to write.
    yara_file -- File to write.
    yara_except_set -- Set of yara rules to discard from the export.
    '''
    yara_name_match = re.search('^(private|global| )*rule\s*\w*',yara_rule,re.MULTILINE)

    if yara_name_match:
        yara_name = yara_name_match.group().replace('rule','').strip(' \t\n\r')
        yara_name_match_import = re.search('^import',yara_rule,re.MULTILINE)
        if not yara_name_match_import:
            if yara_name not in yara_processed and yara_name not in yara_except_set: #avoid duplicates and unwanted rules
                yara_processed.add(yara_name)
                yara_export_file.write(yara_rule)
                yara_export_file.write('\n')

def _export_snort(snort_rule,snort_file):
    '''Write snort_rule in snort_file

    snort_rule -- Yara rule to write.
    snort_file -- File to write.
    '''
    snort_name_match = re.search('msg:\"[^"]*";',snort_rule,re.MULTILINE)

    if snort_name_match:
        snort_name = snort_name_match.group()
        snort_name = snort_name[5:-2]

        if snort_rule not in snort_processed: #avoid duplicates
            snort_processed.add(snort_rule)
            snort_rule = snort_rule.replace('msg:"','msg:"[MISP] ')
            snort_export_file.write(snort_rule)
            snort_export_file.write('\n')

def _read_attribute_tracking_file(tracking_filepath):
    '''Read a csv formatted file that should contain a list of uuid,date of attributes and return a dictionary using uuid as key and date as value.

    tracking_filepath -- Path of the csv formatted file ("," as separator) that contains a list of uuid,date of attributes processed.
    '''
    dic = {}
    if os.path.exists(tracking_filepath):
        if os.path.isfile(tracking_filepath):
            with open(tracking_filepath, 'r') as tracking_file:
                csv_reader = csv.reader(tracking_file, delimiter=',')
                for row in csv_reader:
                    dic[row[0]] = row[1]

            tracking_file.close()

    return dic

def _update_attribute_tracking_file(tracking_filepath, tracking_dict):
    '''Convert a dictionary using attribute uuid as key and attribute date as value into a csv formatted file that should contain a list of uuid,date of attributes.

    tracking_filepath -- Path of the csv formatted file ("," as separator) that contains a list of uuid,date of attributes processed.
    tracking_dict -- Dictionary using attribute uuid as key and attribute date as value.
    '''
    with open(tracking_filepath, 'w') as tracking_file:
        for key in tracking_dict:
            tracking_file.write(key + ',' + tracking_dict[key] + '\n')

    tracking_file.close()

def _add_to_mailed_attributes(event, attribute, reason):
    '''Add the attribute and reason of failure to the set of attribute that will be sent by mail.

    event -- Event realted to the attribute.
    attribute -- Attribute to add to the set of mailed attributes.
    reason -- contains the reason of the failure.
    '''
    mailed_attributes.add((event['Orgname'], event['Orgcname'], event['uuid'], attribute['uuid'], event['info'], reason))

def _send_attributes_mail(mail_address, attribute_set):
    '''Send the the content of attribute_set by mail to mail_address

    attribute_set -- contains the attributes contents.
    mail_address -- contain the mail address that will recieve the results.
    '''

    msg = 'List of problems with IOCs : \n\n'
    msg += 'Org / OrgC / Event UUID / Attribute UUID / Description / Error message \n\n'

    for result in attribute_set:
       msg += str(result[0]) + ' / ' + str(result[1]) + ' / ' + str(result[2]) + ' / ' + str(result[3]) + '\n'

    mime_msg = MIMEText(msg)
    mime_msg['Subject'] = '[MISP-EU] MISP Quality check'
    s = smtplib.SMTP(MAIL_SERVER)
    s.sendmail(MAIL_FROM, mail_address, mime_msg.as_string())
    s.quit()

def check_last(misp, last="1d", datasrc_dict=None, allowed_attribute_set=None, quiet=False, attribute_status_dict={}, stix_export_file=None, yara_export_file=None, snort_export_file=None, to_mail=False):
    '''Check attributes from events published during the last period defined.

    misp -- misp instance connected.
    last -- last period used to catch events. (default 1d)
    datasrc_dict -- dict that contains data source sets used for checks. (default None)
    allowed_attribute_set -- set that contains the misp attibute types that would be checked. (default None)
    quiet -- define if processing output should be displayed. (default False)
    attribute_status_dict -- define the file used to track attributes processed. (default {})
    yara_export_file -- define the file used to export valid yara rules. (default None)
    snort_export_file -- define the file used to export valid snort rules. (default None)
    to_mail -- define if the set of attributes that should be mailed have to be filled. (default False)
    '''
    res = misp.download_last(last)

    if  'response' in res.keys():
        json_events = res['response']
    else:
        if not quiet:
            print 'No attributes in the specified period'
        return
    j=0

    for result in check_attributes(json_events,datasrc_dict,allowed_attribute_set, attribute_status_dict):
        if result:
            j+=1
            if stix_export_file is not None and result['result'] == 'OK':
                if result['attribute_dict']['type'] in stix_supported:
                    stix_indicators.add(_get_stix_indicator(result['attribute_dict']['value'],result['attribute_dict']['uuid'], stix_export_file))

            if yara_export_file is not None and result['result'] == 'OK':
                if result['attribute_dict']['type'] == 'yara':
                    _export_yara(result['attribute_dict']['value'], yara_export_file,datasrc_dict['yara_export_except'])

            if snort_export_file is not None and result['result'] == 'OK':
                if result['attribute_dict']['type'] == 'snort':
                    _export_snort(result['attribute_dict']['value'], snort_export_file)

            if to_mail and result['result'] == 'NOK':
                _add_to_mailed_attributes(result['event_dict'], result['attribute_dict'], result['reason'])

            yield get_CEF_syslog(_get_misp_version(misp), result['event_dict'], result['attribute_dict'], result['result'], result['reason'])

    if not quiet:
        print 'Processing of last ' + last + ' : ' + str(j) + ' attributes processed'

def sliced_search(misp, date_from=None, date_to=None, day_slice=1, time_wait=0, datasrc_dict=None, allowed_attribute_set=None, quiet=False, attribute_status_dict={}, stix_export_file=None, yara_export_file=None, snort_export_file=None, to_mail=False):
    '''Check attributes from events created during the given time range.

    misp -- misp instance connected.
    date_from -- start date of the range. (default None)
    date_to -- end date of the range. (default None)
    day_slice -- define that size in days of subranges generated to check events in order to perform checks in smaller. (default 1)
    time_wait -- define the time to wait between checks of two subranges generated by the day_slice parameter in order to reduce misp server request load. (default 0)
    datasrc_dict -- dict that contains data source sets used for checks. (default None)
    allowed_attribute_set -- Dictionary using attribute uuid as key and attribute date as value used to track attributes updates. (default None)
    quiet -- define if processing output should be displayed. (default False)
    attribute_status_dict -- define the file used to track attributes processed. (default {})
    yara_export_file -- define the file used to export valid yara rules. (default None)
    snort_export_file -- define the file used to export valid snort rules. (default None)
    to_mail -- define if the set of attributes that should be mailed have to be filled. (default False)
    '''
    datelist = _create_date_list(date_from, date_to, day_slice)

    for i in range(0,len(datelist) - 1):
        res = misp.search(date_from=datelist[i],date_to=datelist[i+1])
        if  'response' in res.keys():
            json_events = res['response']
        else:
            if not quiet:
                print 'Processing from ' + datelist[i] + ' to ' + datelist[i+1] + ': No attributes'

            yield None
            continue
        j=0

        for result in check_attributes(json_events,datasrc_dict,allowed_attribute_set, attribute_status_dict):
            if result:
                j+=1
                if stix_export_file is not None and result['result'] == 'OK':
                    if result['attribute_dict']['type'] in stix_supported:
                        stix_indicators.add(_get_stix_indicator(result['attribute_dict']['value'],result['attribute_dict']['uuid'], stix_export_file))

                if yara_export_file is not None and result['result'] == 'OK':
                    if result['attribute_dict']['type'] == 'yara':
                        _export_yara(result['attribute_dict']['value'], yara_export_file, datasrc_dict['yara_export_except'])

                if snort_export_file is not None and result['result'] == 'OK':
                    if result['attribute_dict']['type'] == 'snort':
                        _export_snort(result['attribute_dict']['value'], snort_export_file)

                if to_mail and result['result'] == 'NOK':
                    _add_to_mailed_attributes(result['event_dict'], result['attribute_dict'], result['reason'])

                yield get_CEF_syslog(_get_misp_version(misp), result['event_dict'], result['attribute_dict'], result['result'], result['reason'])

        if not quiet:
            print 'Processing from ' + datelist[i] + ' to ' + datelist[i+1] + ': ' + str(j) + ' attributes processed'

        time.sleep(int(time_wait))

def update_tracking_last(misp, last="1d", allowed_attribute_set=None, quiet=False, attribute_status_dict={}):
    '''Update the attribute tracking file using the last function to fetch events.

    misp -- misp instance connected.
    last -- last period used to catch events. (default 1d)
    allowed_attribute_set -- set that contains the misp attibute types that would be checked. (default None)
    quiet -- define if processing output should be displayed. (default False)
    attribute_status_dict -- define the file used to track attributes processed. (default {})
    '''
    res = misp.download_last(last)

    if  'response' in res.keys():
        json_events = res['response']
    else:
        if not quiet:
            print 'No attributes in the specified period'
        return
    j=0

    for result in track_attributes(json_events,allowed_attribute_set, attribute_status_dict):
        if result:
            j+=1

    if not quiet:
        print 'Processing of last ' + last + ' : ' + str(j) + ' attributes processed'

def update_tracking(misp, date_from=None, date_to=None, day_slice=1, time_wait=0, allowed_attribute_set=None, quiet=False, attribute_status_dict={}):
    '''Update the attribute tracking file using the range search function to fetch events.

    misp -- misp instance connected.
    date_from -- start date of the range. (default None)
    date_to -- end date of the range. (default None)
    day_slice -- define that size in days of subranges generated to check events in order to perform checks in smaller. (default 1)
    time_wait -- define the time to wait between checks of two subranges generated by the day_slice parameter in order to reduce misp server request load. (default 0)
    allowed_attribute_set -- Dictionary using attribute uuid as key and attribute date as value used to track attributes updates. (default None)
    quiet -- define if processing output should be displayed. (default False)
    attribute_status_dict -- define the file used to track attributes processed. (default {})
    '''
    datelist = _create_date_list(date_from, date_to, day_slice)

    for i in range(0,len(datelist) - 1):
        res = misp.search(date_from=datelist[i],date_to=datelist[i+1])
        if  'response' in res.keys():
            json_events = res['response']
        else:
            if not quiet:
                print 'Processing from ' + datelist[i] + ' to ' + datelist[i+1] + ': No attributes'
            continue

        j=0
        for result in track_attributes(json_events,allowed_attribute_set, attribute_status_dict):
            if result:
                j+=1

        if not quiet:
            print 'Processing from ' + datelist[i] + ' to ' + datelist[i+1] + ': ' + str(j) + ' attributes processed'

        time.sleep(int(time_wait))

############################################
#################  Main ####################
############################################

if __name__ == '__main__':
    '''

    '''
    parser = argparse.ArgumentParser(description='Download events from a MISP instance and verify their validity.')
    parser.add_argument("--print_types",help="Print valid MISP attribute types", action="store_true")
    parser.add_argument("--update_tracking_only", help="update the file used to track already processed attributes. Should be used with -s and -e.", action="store_true")
    parser.add_argument("--lock", help="Specify a lock file to prevent multiple execution.")
    parser.add_argument("-l", "--last", help="can be defined in days, hours, minutes (for example 5d or 12h or 30m)")
    parser.add_argument("-s", "--start", help="start date of time range YYYY-MM-DD format")
    parser.add_argument("-e", "--end", help="end date of time range YYYY-MM-DD format")
    parser.add_argument("-d", "--day_slice",help="size of dayrange in days")
    parser.add_argument("-t", "--time_wait",default=0,help="time to wait between processing of 2 range of days in seconds")
    parser.add_argument("-i", "--ip", help="Syslog server ip")
    parser.add_argument("-p", "--port", help="Syslog server port")
    parser.add_argument("-x", "--stix_export_path", help="Valid ioc STIX format file path (only for hashes)")
    parser.add_argument("-y", "--yara_export_path", help="Valid yara rules export file path")
    parser.add_argument("-z", "--snort_export_path", help="Valid snort rules export file path")
    parser.add_argument("-a", "--attribute_tracking", help="file used to track already processed attributes based on its uuid and modification date")
    parser.add_argument("-m", "--mail", help="Email that will receive results of wrong IOCs.")

    argtypegroup = parser.add_mutually_exclusive_group()
    argtypegroup.add_argument("-o", "--only", nargs="+",help="Only attribute type given")
    argtypegroup.add_argument("-w", "--without", nargs="+",help="Without attribute type given")

    argverb_group = parser.add_mutually_exclusive_group()
    argverb_group.add_argument("-v", "--verbose", help="Print the result of each test of attributes.", action="store_true")
    argverb_group.add_argument("-q", "--quiet", help="Suppress all outputs", action="store_true")

    args = parser.parse_args()

    if args.print_types:
        print 'List of valid attributes : '
        for e in allowed_attribute_set:
            print e
        exit(0)

    if not args.quiet:
        print time.strftime("%c")

    if args.lock:
        if os.path.exists(args.lock):
            if os.path.isfile(args.lock):
                print "Lock file already exists. Please wait until the other process has finished or delete this file."
                exit(0)
            else:
                print "Lock file path already exists but it is not a file. Please suppress it."
                exit(0)
        else:
            with open(args.lock, 'w') as lock_file:
                lock_file.write('1\n')
            lock_file.close()

    if args.stix_export_path:
        stix_export_file = open(args.stix_export_path, 'w')
    else:
        stix_export_file = None

    if args.yara_export_path:
        yara_export_file = open(args.yara_export_path, 'w')
    else:
        yara_export_file = None

    if args.snort_export_path:
        snort_export_file = open(args.snort_export_path, 'w')
    else:
        snort_export_file = None

    if args.only:
        if any(e not in allowed_attribute_set for e in args.only):
            print 'Some elements of the attribute list are not valid. Use --print_types, to show the valid ones'
            exit(0)
        else:
            allowed_attribute_set.clear()
            for e in args.only:
                allowed_attribute_set.add(e)

    if args.without:
        if any(e not in allowed_attribute_set for e in args.without):
            print 'Some elements of the attribute list are not valid. Use --print-types, to show the valid ones'
            exit(0)
        else:
            for e in args.without:
                allowed_attribute_set.remove(e)

    if not args.update_tracking_only:
        datasrc_dict = import_external_sources(allowed_attribute_set) # Load datasets

    if args.attribute_tracking:
        attribute_status_dict = _read_attribute_tracking_file(args.attribute_tracking)
        if os.path.exists(args.attribute_tracking):
            if os.path.isfile(args.attribute_tracking):
                copyfile(args.attribute_tracking, args.attribute_tracking + '.bak')

    misp = PyMISP(misp_url, misp_key, misp_verifycert, 'json')

    sock = None

    if args.ip is not None and args.port is not None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((args.ip,int(args.port)))

    if args.update_tracking_only:
        if not args.attribute_tracking:
            print "-a or --attribute_tracking parameter missing."
            exit(0)
        
        if args.last: 
            update_tracking_last(misp,args.last,allowed_attribute_set, args.quiet, attribute_status_dict)
   
        else:
            print "-l/--last or, -s/--start and -e/--end parameters missing."
            exit(0)

            if args.day_slice is None:
                date_format = "%Y-%m-%d"
                delta = datetime.datetime.strptime(args.end,date_format) - datetime.datetime.strptime(args.start,date_format)
                update_tracking(misp,args.start,args.end,str(int(delta.days)),0,allowed_attribute_set, args.quiet, attribute_status_dict)
            else:
                update_tracking(misp,args.start,args.end,args.day_slice,args.time_wait,allowed_attribute_set,args.quiet,attribute_status_dict)

    elif args.last is not None:
        for message in check_last(misp,args.last,datasrc_dict, allowed_attribute_set, args.quiet, attribute_status_dict, stix_export_file, yara_export_file, snort_export_file, bool(args.mail)):
            if args.verbose and message is not None:
                print message
            if isinstance(sock,socket.socket) and message is not None:
                sock.send(message)

    elif args.day_slice is None:
        date_format = "%Y-%m-%d"
        delta = datetime.datetime.strptime(args.end,date_format) - datetime.datetime.strptime(args.start,date_format)
        for message in sliced_search(misp,args.start,args.end,str(int(delta.days)),0,datasrc_dict, allowed_attribute_set, args.quiet, attribute_status_dict, stix_export_file, yara_export_file, snort_export_file, bool(args.mail)):
            if args.verbose and message is not None:
                print message
            if isinstance(sock,socket.socket) and message is not None:
                sock.send(message)

    else:
        for message in sliced_search(misp,args.start,args.end,args.day_slice,args.time_wait,datasrc_dict, allowed_attribute_set, args.quiet, attribute_status_dict, stix_export_file, yara_export_file, snort_export_file, bool(args.mail)):
            if args.verbose and message is not None:
                print message
            if isinstance(sock,socket.socket) and message is not None:
                sock.send(message)

    if isinstance(sock,socket.socket):
        sock.close()

    if args.stix_export_path:
        stix_package = STIXPackage()
        stix_header = STIXHeader()
        stix_header.description = "MISP checkioc STIX export"
        stix_package.stix_header = stix_header

        for indicator in stix_indicators:
            stix_package.add(indicator)

        stix_export_file.write(stix_package.to_xml())

        stix_export_file.close()

    if args.yara_export_path:
        yara_export_file.close()

    if args.snort_export_path:
        snort_export_file.close()

    if args.attribute_tracking:
        _update_attribute_tracking_file(args.attribute_tracking, attribute_status_dict)
        if os.path.exists(args.attribute_tracking + '.bak'):
            if os.path.isfile(args.attribute_tracking + '.bak'):
                os.remove(args.attribute_tracking + '.bak')

    if args.mail:
        _send_attributes_mail(args.mail, mailed_attributes)

    if args.lock:
        if os.path.exists(args.lock):
            if os.path.isfile(args.lock):
                os.remove(args.lock)

    if not args.quiet:
        print time.strftime("%c")

    exit(0)
