#! /bin/env python3
'''
Get windows-logs in a format readable by most logfile-readers
https://github.com/DominikSchlecht/evtxtolog
'''
__description__ = 'Get windows-logs in a format readable by most logfile-readers'
__author__ = 'Dominik Schlecht @DominikSchlecht'
__version__ = '0.1'
__date__ = '2019-01-23'

import argparse
import Evtx.Evtx as evtx
import Evtx.Views as e_views
import xml.etree.ElementTree as ET

from Evtx.BinaryParser import OverrunBufferException

def _load_event_map():
    ''' Load the event.map file containing description for all 
    events. Map is based on https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx '''
    with open('event.map','r') as inf:
        dict_from_file = eval(inf.read())
    return dict_from_file

NAMESPACE = '{http://schemas.microsoft.com/win/2004/08/events/event}'
EVENT_MAP = _load_event_map()

def get_xml_from_evtx(evtx_file):
    ''' Get the XML from an evtx file thanks to the 
    python-evtx module. '''
    xml_string = ''
    with evtx.Evtx(evtx_file) as log:
        xml_string += e_views.XML_HEADER
        xml_string += "<Events>"
        for record in log.records():
            # Catch the Overrun, to be fixed in python-evtx..
            try:
                tmp = record.xml()
                if tmp != '':
                    xml_string += tmp.strip()
            except OverrunBufferException:
                pass
        xml_string += "</Events>"
        return xml_string

def _multiline_to_singleline(multiline):
    ''' Take a multiline entry and convert it to single line. '''
    singleline = ''
    for single_val in multiline.split('\n'):
        singleline += single_val.strip() + ", "
    
    return "[{}]".format(singleline[:-2])

def _get_basic_information(event):
    ''' Extract basic info from the System-Section of the event. '''
    system = event.find(NAMESPACE + "System")
    date = system.find(NAMESPACE + "TimeCreated").attrib['SystemTime']
    computer = system.find(NAMESPACE + "Computer").text
    event_id = system.find(NAMESPACE + "EventID").text
    if event_id in EVENT_MAP.keys():
        desc = EVENT_MAP[event_id]
    else:
        desc = ' - '
    
    return "[{date} {computer}:{event_id}] [{desc}]".format(
        date=date,
        computer=computer,
        event_id=event_id,
        desc=desc
    )

def _get_enhanced_information(event):
    ''' Get the enhaced information from (mainly) the 
    event_data section. '''
    log_line = ''
    event_data = event.find(NAMESPACE + "EventData")
    if event_data:
        for data_elem in event_data:
            try:
                # Fetch the data
                value = data_elem.text
               
                # If it is multilined, convert to single line list
                if value is not None and '\n' in value:
                    value = _multiline_to_singleline(value)
                
                # Add additional data to logline
                log_line += " {}={}".format(
                    data_elem.attrib['Name'],
                    value
                )
            except KeyError:
                # Most likely a bug in python-evtx (event_id 8222)
                pass
    return log_line

def get_log_from_xml(xml_string):
    ''' Get together all the information about the events and return 
    the full string. '''
    # tree = ET.fromstring(xml_string)
    # tree = ET.parse('out')
    # root = tree.getroot()
    
    root = ET.fromstring(xml_string)
    
    ret = ''
    for event in root:
        # Get basic infos from system
        log_line = _get_basic_information(event)
        
        # Get further information based on event
        log_line += _get_enhanced_information(event)
        ret += log_line + "\n"
    return ret

def main():
    # Init the parser
    parser = argparse.ArgumentParser()
    parser.add_argument("evtx_file")
    parser.add_argument("output_file")
    args = parser.parse_args()
    
    xml_string = get_xml_from_evtx(args.evtx_file)
    out = open(args.output_file, 'w')
    out.write(get_log_from_xml(xml_string))
    out.close()

if __name__ == '__main__':
    main()
