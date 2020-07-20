#!/usr/bin/python

'''

@author: Denis Gudtsov
'''

import pyshark
import sys

import json

import gzip

#cap_filter='diameter.Subscription-Id-Data == "12345668" && ip.addr==10.1.42.53'
cap_filter='ip.addr==10.1.42.53'
cap_filter='!(diameter.applicationId == 4)'

# headers per each protocol that will be extracted
headers = {

           "diameter": {
#                        "long":
#                                [
#                                 'subs_req_type',
#                                 ,'abort_cause','termination_cause'
#                                 ]
                        "short":
                                ['flags_request','cc_request_type','cmd_code','experimental_result_code','result_code','session_id','subscription_id_data','rat_type','framed_ip_address']
                        }

    }

proto_msg_skip = {

                  "diameter" : {
                                 "cmd_code": ['280']
                                 }
                  }


uml_draw_keys = ['local','method','cmd_code','request_method']

# Universal class to process sip, diameter, map and camel messages
class Message(object):
    """
    Base class for Message object (extends Layer representation).
    """

    frame_num = 0

    msg_params = {}
    msg_digest = {}

    draw_key = None

    def __init__(self,layer):
        self.msg_params = dict()
        self.msg_digest = dict()

        self.proto = layer.layer_name
        self.process_headers(layer)
        self.layer = layer
        
        # [a[s] for s in a if "sip2" in s]
 
        # filling object's list according to proto value
        # if message is not defined in skip, then will be ''
#        self.msg_skip = [proto_msg_skip[s] for s in proto_msg_skip if self.proto in s]
        
        if self.proto in proto_msg_skip:
            self.msg_skip = proto_msg_skip[self.proto]

        self.__draw_key__()

    def __draw_key__(self):
        for i in uml_draw_keys:
            if i in self.msg_params:
                self.draw_key = self.msg_params[i]

    def add_param(self,key,value):
        self.msg_params[key] = value

    def __getattr__(self,key):
        """
        Gets the key in the given key name.
        :param key: packet index
        :return: attribute value.
        """
        return self.msg_params[key]

    def process_headers (self, layer):

#        for avp_type in headers['diameter']:
#            for avp in headers['diameter'][avp_type]:

        for header_type in headers[layer.layer_name]:

#        msg_headers = headers[layer.layer_name]
#        for header in msg_headers:
            for header in headers[layer.layer_name][header_type]:
                self.extract_header(layer, header, header_type)

    def extract_header (self, layer, header, header_type):
        value = layer.get_field(header)
#        self.msg_params[header] = value.showname if (value != None) else ""

        if value == None:
            self.msg_params[header] = ""
        else:
            # todo add += in case notifeff
            if header_type == "long":
                self.msg_params[header] = value.showname
            else:
                self.msg_params[header] = value.show

# leaved for future use
    def __format__(self, format):

        (keyname,method) = format.partition('.')[::2]

        if method == 'showname':
            result = self.layer.get_field(keyname).showname
        else:
            result = self.layer.get_field(keyname)

        pass
        return result
    
    def skip(self):
        #                     if (layer.cmd_code not in proto_msg_skip[layer.layer_name]['cmd_code']) :
        if (self.msg_params['cmd_code'] not in self.msg_skip['cmd_code']):
            return False
        return True




if __name__ == '__main__':

    session_ids=dict()
    
    cap_file = sys.argv[1]
    result_file = sys.argv[2]
    
    print "source file: "+cap_file
    print "result file: "+result_file
    
    try:
        cap = pyshark.FileCapture(input_file=cap_file, display_filter=cap_filter)
    except:
        sys.stderr.write("source pcap file is not found %s \n",sys.exc_info())
        exit 

    with gzip.open(result_file, 'w') as fp:
        
        print "processing..."

        for i,frame in enumerate(cap):
            
            if 'diameter' in frame:
                        
                for layer in frame.layers:
                    if (layer.layer_name in ['diameter']):
                        
                        record = dict()
                        
    #                    if (layer.cmd_code not in proto_msg_skip[layer.layer_name]['cmd_code']) :
                        DIAM = Message (layer)
    
                        record['time_epoch'] = frame.frame_info.time_epoch.show
    #                    print frame.frame_info.number
                                            
                        if not DIAM.skip():
    
    #                        DIAM.add_param("src",Participant(frame.ip.src).name)
    #                        DIAM.add_param("dst",Participant(frame.ip.dst).name)
                            
                            record['cmd_code'] = int(DIAM.cmd_code)
                            record['flags_request'] = int(DIAM.flags_request)
                            record['session_id'] = DIAM.session_id
                            
                            if (DIAM.cc_request_type != ""):
                                record['cc_request_type'] = int(DIAM.cc_request_type)
                                                                            
                            if (DIAM.flags_request == '1'):
                                if DIAM.cmd_code=='272':
                                    record['subscription_id_data'] = DIAM.subscription_id_data
                                    if (DIAM.rat_type != ""):
                                        record['rat_type'] = int(DIAM.rat_type)
                                    if (DIAM.framed_ip_address !=""):
                                        record['framed_ip_address'] = DIAM.framed_ip_address 
                                    
    #                            record['result_code'] = None
                            else:
                                if (DIAM.result_code != ""):
                                    record['result_code'] = int(DIAM.result_code)
    
    
#                            print json.dumps(record)
                            json.dump(record,fp)
                            fp.write("\n")
    print "done"
                            

