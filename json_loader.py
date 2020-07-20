#!/usr/bin/python
# encoding: utf-8
'''
json_loader -- shortdesc

json_loader is a description

It defines classes_and_methods

@author:     Denis Gudtsov

@copyright:  2020. All rights reserved.

@license:    license

@contact:    user_email
@deffield    updated: Updated
'''

'''
CREATE TABLE `diam` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `time_epoch` datetime(6) NOT NULL,
  `cmd_code` int(4) unsigned NOT NULL,
  `cc_request_type` int(2) DEFAULT NULL,
  `session_id` varchar(255) NOT NULL,
  `flags_request` int(10) unsigned NOT NULL,
  `result_code` int(11) DEFAULT NULL,
  `subscription_id_data` varchar(20) DEFAULT NULL,
  `rat_type` int(5) DEFAULT NULL,
  `framed_ip_address` int(10) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`),
  KEY `idx_diam_session_id` (`session_id`),
  KEY `idx_diam_subscription_id_data` (`subscription_id_data`)
);
'''

import sys
import os
import time
import socket
import struct

import gzip

import json

from argparse import ArgumentParser
from argparse import RawDescriptionHelpFormatter

__all__ = []
__version__ = 0.1
__date__ = '2020-06-22'
__updated__ = '2020-06-22'

DEBUG = 1
TESTRUN = 0
PROFILE = 0

import pymysql.cursors

# Connect to the database
connection = pymysql.connect(host='10.31.74.222',
                             user='pcap',
                             password='',
                             db='pcap',
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)

optional_keys=['cc_request_type','result_code','rat_type','subscription_id_data','framed_ip_address']

batch_size=5000

def mysql_insert(js):
    
    for i in js:
    
        for key in optional_keys:
            if key not in i.keys():
                i[key]=None
            pass
    
    try:
        with connection.cursor() as cursor:
            # Create a new record
#            sql = "INSERT INTO `diam` (`cmd_code`, `session_id`, 'flags_request', 'time_epoch') VALUES (%s, %s, %s, %s)"
#            sql = "INSERT INTO diam(cmd_code,session_id,flags_request,time_epoch,cc_request_type,result_code,rat_type,subscription_id_data,framed_ip_address) VALUES (%(cmd_code)s, %(session_id)s, %(flags_request)s, %(time_epoch)s,%(cc_request_type)s,%(result_code)s,%(rat_type)s,%(subscription_id_data)s,INET_ATON(%(framed_ip_address)s))"
            sql = "INSERT INTO diam(cmd_code,session_id,flags_request,time_epoch,cc_request_type,result_code,rat_type,subscription_id_data,framed_ip_address) VALUES (%(cmd_code)s, %(session_id)s, %(flags_request)s, %(time_epoch)s,%(cc_request_type)s,%(result_code)s,%(rat_type)s,%(subscription_id_data)s,%(framed_ip_address)s)"
#            sql = "INSERT INTO diam(cmd_code,session_id,flags_request,time_epoch) VALUES (%(cmd_code)s, %(session_id)s, %(flags_request)s, %(time_epoch)s)"
            
            cursor.executemany(sql, js)
    
        # connection is not autocommit by default. So you must commit to save
        # your changes.
        connection.commit()
        
        print "inserted: "+str(cursor.rowcount)+"\n"
        
    except Exception:
        print "error inserting row: " # + json.dumps(js) + "\n"
        print cursor._last_executed
        print "\n"
    return

def json_parse (input_file):
    
    with gzip.open(input_file, 'r') as f_inp:
        
        print "processing... batch size: "+str(batch_size)+"\n"

        exit=False
        
        while True:
            
            json_list=[]
            
            for i in range(batch_size):
                
                data=f_inp.readline()
                if not data:
                    exit=True
                    break
                j = json.loads(data)
    
            # time conversion            
                (seconds,mseconds) = j['time_epoch'].split('.')
                str_datetime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(j['time_epoch'])))+"."+str(int(mseconds))
                j['time_epoch']= str_datetime
                
            # ip address conversion
                if 'framed_ip_address' in j.keys(): 
                    if j['framed_ip_address'] != "" :
                        octets = j['framed_ip_address'].split(':')
                        ip=[]
                        for octet in octets:
                             ip.append(str(int(octet,16)))
                        
                        framed_ip_str=".".join(ip)
#                        j['framed_ip_address'] = framed_ip_str
                        framed_ip_int = struct.unpack("!I", socket.inet_aton(framed_ip_str))[0]
                        j['framed_ip_address'] = framed_ip_int
#                    else:
#                        j['framed_ip_address']="0.0.0.0"
#                else:
#                    j['framed_ip_address']="0.0.0.0"
                
                json_list.append(j)
                
    #            print j
                
                
            mysql_insert(json_list)
                
            if exit==True:
                break
    
    print "done"
    
    return

class CLIError(Exception):
    '''Generic exception to raise and log different fatal errors.'''
    def __init__(self, msg):
        super(CLIError).__init__(type(self))
        self.msg = "E: %s" % msg
    def __str__(self):
        return self.msg
    def __unicode__(self):
        return self.msg

def main(argv=None): # IGNORE:C0111
    '''Command line options.'''

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = '''%s

  Created by user_name on %s.
  Copyright 2020 organization_name. All rights reserved.

  Licensed under the Apache License 2.0
  http://www.apache.org/licenses/LICENSE-2.0

  Distributed on an "AS IS" basis without warranties
  or conditions of any kind, either express or implied.

USAGE
''' % (program_shortdesc, str(__date__))

    try:
        # Setup argument parser
        parser = ArgumentParser(description=program_license, formatter_class=RawDescriptionHelpFormatter)
        parser.add_argument("-r", "--recursive", dest="recurse", action="store_true", help="recurse into subfolders [default: %(default)s]")
        parser.add_argument("-v", "--verbose", dest="verbose", action="count", help="set verbosity level [default: %(default)s]")
        parser.add_argument('-V', '--version', action='version', version=program_version_message)
        parser.add_argument(dest="paths", help="paths to folder(s) with source file(s) [default: %(default)s]", metavar="path", nargs='+')

        # Process arguments
        args = parser.parse_args()

        paths = args.paths
        verbose = args.verbose
        recurse = args.recurse

        if verbose > 0:
            print("Verbose mode on")
            if recurse:
                print("Recursive mode on")
            else:
                print("Recursive mode off")

        for inpath in paths:
            ### do something with inpath ###
            print(inpath)
            json_parse(inpath)
            
        return 0
    except KeyboardInterrupt:
        ### handle keyboard interrupt ###
        return 0
#     except Exception, e:
#         if DEBUG or TESTRUN:
#             raise(e)
#         indent = len(program_name) * " "
#         sys.stderr.write(program_name + ": " + repr(e) + "\n")
#         sys.stderr.write(indent + "  for help use --help")
#         return 2

if __name__ == "__main__":
    if DEBUG:
        sys.argv.append("-v")
    if TESTRUN:
        import doctest
        doctest.testmod()
    if PROFILE:
        import cProfile
        import pstats
        profile_filename = 'json_loader_profile.txt'
        cProfile.run('main()', profile_filename)
        statsfile = open("profile_stats.txt", "wb")
        p = pstats.Stats(profile_filename, stream=statsfile)
        stats = p.strip_dirs().sort_stats('cumulative')
        stats.print_stats()
        statsfile.close()
        sys.exit(0)
    sys.exit(main())