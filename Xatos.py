#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from os import path, linesep
from fileinput import (input as fi_input, close as fi_close)
from re import compile as re_compile
from subprocess import check_output as sp_co
from sys import argv as sys_argv

__author__ = 'Xiao Wang, linhan.wx'

class Xatos(object):
    """
    http://stackoverflow.com/a/13576028/562154
    symbol address = slide + stack address - load address
    The slide value is the value of vmaddr in LC_SEGMENT cmd (Mostly this is 0x1000). Run the following to get it:
    xcrun -sdk iphoneos otool -arch ARCHITECTURE -l "APP_BUNDLE/APP_EXECUTABLE"  | grep -A 10 "LC_SEGMENT" | grep -A 8 "__TEXT"|grep vmaddr
    Replace ARCHITECTURE with the actual architecture the crash report shows, e.g. armv7. Replace APP_BUNDLE/APP_EXECUTABLE with the path to the actual executable.
    The stack address is the hex value from the crash report.
    The load address is the first address showing in the Binary Images section at the very front of the line which contains your executable. (Usually the first entry).
    """

    def __init__(self, crashlog_path, dsym_or_app_path):
        self.crashlog_path = self.get_abs_path(crashlog_path)
        self.dsym_or_app_path = self.get_abs_path(dsym_or_app_path)
        self.get_crashlog_info()
        self.bin_line_ptn = re_compile('^\d+\s+{}\s+(0x[0-9a-f]+)\s+'.format(self.bin_name))
        # self.slide_addr = self.get_slide_addr()
        self.load_addr_ptn = re_compile('^\d+\s+{}\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+\+\s+\d+'.format(self.bin_name))

    @staticmethod
    def get_abs_path(a_path):
        abs_path = path.abspath(a_path)
        if path.exists(abs_path):
            return abs_path
        else:
            raise SystemExit('File not found: {}'.format(abs_path))

    def desymbolicate_file(self):
        desym_result = self.desymbolicate()
        for line in fi_input(self.crashlog_path, backup='.dbak', inplace=1):
            if line in desym_result.keys():
                print desym_result[line]
            else:
                print line.rstrip()
        fi_close()


    def get_crashlog_info(self):
        bin_img_line_flag = False
        bin_img_line = ''
        with open(self.crashlog_path) as crash_fp:
            for line in crash_fp:
                if bin_img_line_flag:
                    bin_img_line = line
                    bin_img_line_flag = False
                if 'Binary Images:' in line:
                    bin_img_line_flag = True
        if not bin_img_line:
            raise SystemExit('Cannot find crash app binary image info')
        bin_img_info = [i for i in bin_img_line.rstrip().split() if i and i != '-']
        self.load_addr, end_laddr, bin_name, bin_arch, bin_uuid, bin_path = bin_img_info
        if bin_uuid.startswith('<') and bin_uuid.endswith('>'):
            self.bin_uuid = bin_uuid[1:-1]
        self.bin_name = bin_name
        self.bin_uuid = bin_uuid
        self.bin_arch = bin_arch

    def desymbolicate(self):
        desym_result = {}
        with open(self.crashlog_path) as crash_fp:
            for line in crash_fp:
                if self.bin_line_ptn.search(line):
                    desym_result.setdefault(line)
        all_stack_addr = []
        lines = desym_result.keys()
        for line in lines:
            line_header = self.bin_line_ptn.search(line)
            result = self.load_addr_ptn.findall(line)
            if result:
                stack_addr, load_addr = result[0]
                assert load_addr == self.load_addr, 'Crashlog is invalid, load address is not the same'
            else:
                stack_addr = line_header.group(1)
                assert self.load_addr is not None, 'Cannot get load address'
            all_stack_addr.append(stack_addr)
        atos_cmd = ['xcrun', 'atos', '-o', self.dsym_or_app_path, '-l', self.load_addr, '-arch', self.bin_arch]
        atos_cmd.extend(all_stack_addr)
        dsymed = [i for i in sp_co(atos_cmd).split(linesep) if i]
        assert len(lines) == len(dsymed), 'Crashlog desymbolicate error!'
        for idx, line in enumerate(lines):
            desym_result[line] = '{}{}'.format(self.bin_line_ptn.search(line).group(), dsymed[idx])
        return desym_result

    def get_slide_addr(self):
        otool_cmd = ['xcrun', 'otool', '-arch', self.bin_arch, '-l', self.dsym_or_app_path]
        output = sp_co(otool_cmd)
        lines = [i.rstrip() for i in output.split('\n') if i]
        cmd_segment = False
        segname_text = False
        for line in lines:
            if 'cmd LC_SEGMENT' in line:
                cmd_segment = True
            if cmd_segment and 'segname __' in line and 'segname __TEXT' not in line:
                cmd_segment = False
            if 'segname __TEXT' in line:
                segname_text = True
            if cmd_segment and segname_text:
                if 'vmaddr' in line:
                    return line.split()[1]
        raise SystemExit('cannot get binary image slide address')


def main():
    if len(sys_argv) != 3:
        raise SystemExit("""Xatos.py path/to/crashlog.crash path/to/dSYM/binary/or/app/binary
Example:
 1) Xatos.py "MyApp_1986-1-1_Sean-teki-iPhone.crash" "Payload/MyApp.app/MyApp"
 2) Xatos.py "MyApp_1995-6-1_Noelani-teki-iPad.ips" "MyApp.app.dSYM/Contents/Resources/DWARF/MyApp"
        """)
    else:
        Xatos(sys_argv[1], sys_argv[2]).desymbolicate_file()


if __name__ == '__main__':
    main()

