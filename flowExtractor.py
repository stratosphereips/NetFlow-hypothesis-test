#!/usr/bin/env python3.6 -u
# Author: Karel Durkota

import sys
import argparse
import csv
import re
from collections import defaultdict
import pandas as pd
import numpy as np


__version__ = '0.1'
# ['StartTime','Dur','Proto','SrcAddr','Sport','Dir','DstAddr','Dport','State','sTos','dTos','TotPkts','TotBytes','SrcBytes','SrcPkts','Label','srcUdata','dstUdata']
col = dict()

def getHeader(filename):
    global col
    with open(filename, "r") as csvfile:
        return csvfile.readline().split(',')
    print(col)

def getProductionIp(port, filename):

    with open(args.filename, "r") as csvfile:
        d = defaultdict(int)
        reader = csv.reader(csvfile, delimiter=',')
        for row in reader:
            d[row[col['DstAddr']]] += 1
            d[row[col['SrcAddr']]] += 1

        production_ip = max(d.items(), key=lambda x: x[1])
        if (args.debug > 0):
            print('Production IP = {0}'.format(production_ip[0]))
        return production_ip[0]

def getFiltered(ip, port, filename):
    global col

    data = []
    with open(filename, "r") as csvfile:
        csvfile.readline() # read the header

        reader = csv.reader(csvfile, delimiter=',')
        #for row in reader:
        #    print(len(row))

        filtered = filter(lambda p:
                               str(port) == p[col['Dport']] and
                               ip == p[col['DstAddr']] and
                               'tcp' == p[col['Proto']] and
                               re.match('.*S.*_.*', p[col['State']]),
                               reader)

        for row in filtered:
            data.append(row[:len(col)])
    return data

def extract(argv):
    global args

    parser = argparse.ArgumentParser(description="Program filters only the flows that have: i) given IP address in the Destination; ii) given port in the destPort; iii) contains S in the Source state.", usage='%(prog)s --ip <ip_address> --port <port>')
    parser.add_argument('-i', '--ip', help='The destination IP address. If omitted, script searches for IP address that occures in all lines. The header line is assumed to contain DstAddr attribute.', action='store', required=False)
    parser.add_argument('-p', '--port', help='The destination port. The header line is assumed to contain Dport attribute.', action='store', required=True, type=int)
    parser.add_argument('-f', '--filename', help='The CSV file with netflows. The first line is assumed to be header.', action='store', required=argparse.FileType('r'))
    parser.add_argument('-d', '--debug', help='Amount of debugging. This shows inner information about the run.', action='store', default=0, required=False, type=int)
    args = parser.parse_args(argv)


    global col
    header = getHeader(args.filename)
    # ['StartTime','Dur','Proto','SrcAddr','Sport','Dir','DstAddr','Dport','State','sTos','dTos','TotPkts','TotBytes','SrcBytes','SrcPkts','Label','srcUdata','dstUdata']
    col = dict([(header[i], i) for i in range(len(header))])

    if ( args.ip is None ):
        production_ip = getProductionIp(args.port, args.filename)
        print('Production IP is {0}'.format(production_ip))
    else:
        production_ip = args.ip

#    output[0] = header

    # print(getFiltered(production_ip, args.port, args.filename))
    data = getFiltered(production_ip, args.port, args.filename)
    data.insert(0, header)
    return data

if __name__ == "__main__":
    data = extract(sys.argv[1:])
    print(data)
