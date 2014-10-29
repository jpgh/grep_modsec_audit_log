#!/usr/bin/python3
import os
import argparse
from re import compile
from re import search


def parseRes(modSecLog, idO, formatOut):

    if formatOut == 'all':
        for line in modSecLog:
            print(line.strip())
    else:
        for arg in formatOut:
            findArg=False
            argText=''
            for line in modSecLog:
# if find section
                if '--%s-%s--' % (idO, arg) == line.strip():
                    findArg=True
                    argText=line
                    continue

# if search start new sections
                if '--%s-' % idO in line and findArg:
                    print(argText)
                    break

                if findArg:
                    argText+=line



def main():

    strPrev=""
    findObj=False #if true, find require section
    idObjPattern=compile(r'(--)([a-z,0-9]{8})')
    headreq=True
    levelMes=False
    findLv=True

# define cli argument
    parser = argparse.ArgumentParser(description='parse mod_security audit log')
    parser.add_argument('-f', '--file', required=True,\
        help='path to logfile')
    parser.add_argument('-B', '--request_headers', action='store_const',\
        const='B', default='', help='Print request headers')
    parser.add_argument('-C', '--request_body', action='store_const', \
        const='C', default='', help='Print request body')
    parser.add_argument('-F', '--response_headers', action='store_const', \
        const='F', default='', help='Print response headers')
    parser.add_argument('-H', '--trailer', action='store_const', \
        const='H', default='', help='Print audit log trailer')
    parser.add_argument('-E', '--int_resp_body', action='store_const', \
        const='E', default='', help='Print intended response body')
    parser.add_argument('search_string')
    parser.add_argument('-r', '--regexp', action='store_true', \
        help='Find with regexp')
#    parser.add_argument('-l','--level', help='level message :x,a,c,e,w,n,i.d')
    arg = parser.parse_args()

    findStr = arg.search_string
    formatOut = arg.request_headers+arg.request_body+arg.int_resp_body+\
    arg.response_headers+arg.trailer


    if not formatOut: formatOut='all'

    if arg.regexp:
        findStrPattern=compile(findStr)

    try:
        logFile = open(arg.file, "r")
    except:
        print('Error opening log file')
        exit()

#    if arg.level:
#        level = ['DEBUG','INFO','NOTICE','WARNING','ERROR','CRITICAL','ALERT','EMERGENCY']
#        levSh = ['d','i','n','w','e','c','a','x']
#        PosLv=levSh.index(arg.level)


    findRes=[]

    findLv=True
#find in log file
    for line in logFile:

# find start log message pattern and write strings in findRes list
        if '-A--' in line:

            if idObjPattern.match(line):
                findRes = []
                findObj = False
#                findLv = False
                idObj = idObjPattern.search(line).group(2)
            else: print('Warning! Find -A-- in text log.')

        findRes.append(line)

        if arg.regexp:
            if findStrPattern.search(line):
                findObj=True

        elif findStr in line:
            findObj=True

#        if arg.level:
#            findLv = False
#            for i in level[PosLv:]:
#                if i in line: findLv = True

# find end pattern for log message
        if '-Z--' in line and findObj and findLv:
           if idObjPattern.search(line).group(2) == idObj:
                parseRes(findRes, idObj, formatOut)
           else: print('Warning! Error structure audit log. Not end section (-Z--) for measge id %s' % idObj)

# if lenght message very long - error parsing log, exit
        if len(findRes) > 300:
            print('Error! Very long result audit section.')


    logFile.close()

main()

