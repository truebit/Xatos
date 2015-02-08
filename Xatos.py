#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from os import path, linesep, environ
from fileinput import (input as fi_input, close as fi_close)
from re import compile as re_compile
from subprocess import (check_output as sp_co, CalledProcessError)
from sys import (argv as sys_argv, getfilesystemencoding as getfsencoding)

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
        self.get_crashlog_info()
        self.dsym_or_app_path = self.get_dsym_path(dsym_or_app_path)
        self.bin_line_ptn = re_compile('^\d+\s+{}\s+(0x[0-9a-f]+)\s+'.format(self.bin_name))
        self.slide_addr = self.get_slide_addr()
        print 'slide_addr',self.slide_addr
        # load addr example: 17  AliTrip     0x0002b56e 0x21000 + 42350
        self.load_addr_ptn = re_compile('^\d+\s+{}\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+\+\s+\d+'.format(self.bin_name))
        # stack addr example: 2   AliTrip    0x00000001003dc6d8 curl_multi_setopt (in AliTrip) + 788
        self.stack_decimal_ptn = re_compile('^\d+\s+{}\s+(0x[0-9a-f]+)\s+.+\+\s+(\d+)'.format(self.bin_name))
        self.__env = environ.copy()

    @staticmethod
    def get_abs_path(a_path):
        abs_path = path.abspath(a_path.decode(getfsencoding()))
        if path.exists(abs_path):
            return abs_path
        else:
            raise SystemExit('ERROR:: File not found: {}'.format(abs_path))

    def get_dsym_path(self, a_path):
        abs_path = self.get_abs_path(a_path)
        if abs_path.lower().endswith('.dsym'):
            abs_path = path.join(abs_path, 'Contents', 'Resources', 'DWARF', self.bin_name)
        return abs_path

    def desymbolicate_file(self):
        self.symbolicatecrash()
        desym_result = self.desymbolicate()
        for line in fi_input(self.crashlog_path, backup='.dbak', inplace=1):
            if line in desym_result.keys():
                print desym_result[line]
            else:
                print line.rstrip()
        fi_close()
        print "desymbolicated log saved to '{}', original log saved to '{}'".format(self.crashlog_path,
                                                                                    self.crashlog_path + '.dbak')

    def symbolicatecrash(self):
        '''use symbolicatecrash when dSYM file available'''
        try:
            sp_co(['which','xcodebuild'])
            self.__dev_dir = sp_co(['xcode-select', '-p']).rstrip()
        except CalledProcessError as cpe:
            print cpe.output
            print 'WARNING:: Xcode not installed, using "atos" instead of "symbolicatecrash"'
        else:
            self.__symbolicatecrash_path = self.get_symbolicatecrash_path()
            if not self.__env.get('DEVELOPER_DIR'):
                self.__env['DEVELOPER_DIR'] = self.__dev_dir
            if '.dsym' in self.dsym_or_app_path.lower():
                try:
                    output = sp_co([self.__symbolicatecrash_path, self.crashlog_path, self.dsym_or_app_path], env=self.__env)
                    with open(self.crashlog_path, 'w') as f:
                        f.write(output)
                except CalledProcessError:
                    print 'WARNING:: symbolicatecrash failed, will use "atos" only'

    def get_symbolicatecrash_path(self):
        if self.__dev_dir:
            xcode_version_list = sp_co(['xcodebuild', '-version']).rstrip().split()
            xcode_verion = xcode_version_list[xcode_version_list.index('Xcode') + 1]
            if xcode_verion < '4.3':
                return '/Developer/Platforms/iPhoneOS.platform/Developer/Library/PrivateFrameworks/DTDeviceKit.framework/Versions/A/Resources/symbolicatecrash'
            elif xcode_verion < '5':
                return path.join(self.__dev_dir, 'Platforms/iPhoneOS.platform/Developer/Library/PrivateFrameworks/DTDeviceKit.framework/Versions/A/Resources/symbolicatecrash')
            elif xcode_verion < '6':
                return path.join(self.__dev_dir, 'Platforms/iPhoneOS.platform/Developer/Library/PrivateFrameworks/DTDeviceKitBase.framework/Versions/A/Resources/symbolicatecrash')
            else:
                return path.join(path.dirname(self.__dev_dir),'SharedFrameworks/DTDeviceKitBase.framework/Versions/A/Resources/symbolicatecrash')

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
        self.bin_uuid = bin_uuid.strip('<>')
        self.bin_name = bin_name.replace('+', '')
        self.bin_uuid = bin_uuid
        self.bin_arch = bin_arch

    def desymbolicate(self):
        desym_result = {}
        with open(self.crashlog_path) as crash_fp:
            for line in crash_fp:
                if self.bin_line_ptn.search(line):
                    desym_result.setdefault(line)
        all_stack_addr = []
        all_symbol_addr = []
        lines = desym_result.keys()
        stack_decimal_ptn = False
        for line in lines:
            load_addr_result = self.load_addr_ptn.findall(line)
            if load_addr_result:
                stack_addr, load_addr = load_addr_result[0]
                all_stack_addr.append(stack_addr)
                assert load_addr == self.load_addr, 'ERROR:: Crashlog is invalid, load address is not the same'
            stack_addr_result = self.stack_decimal_ptn.findall(line)
            if stack_addr_result:
                stack_decimal_ptn = True
                stack_addr, decimal_sum = stack_addr_result[0]
                assert self.load_addr is not None, 'ERROR:: Cannot get load address'
                symbol_addr = hex(int(self.slide_addr,16)+int(stack_addr,16)-int(self.load_addr,16))
                all_symbol_addr.append(symbol_addr)
        if stack_decimal_ptn:
            atos_cmd = ['xcrun', 'atos', '-o', self.dsym_or_app_path, '-arch', self.bin_arch]
            atos_cmd.extend(all_symbol_addr)
        else:
            atos_cmd = ['xcrun', 'atos', '-o', self.dsym_or_app_path, '-l', self.load_addr, '-arch', self.bin_arch]
            atos_cmd.extend(all_stack_addr)
        try:
            dsymed = [i for i in sp_co(atos_cmd).split(linesep) if i]
        except CalledProcessError as cpe:
            raise SystemExit('ERROR:: ' + cpe.output)
        assert len(lines) == len(dsymed), 'ERROR:: Crashlog desymbolicate error!'
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
        raise SystemExit('ERROR:: cannot get binary image slide address')


def main():
    if len(sys_argv) != 3:
        raise SystemExit("""Xatos.py path/to/crashlog.crash path/to/dSYM/or/app/binary
Example:
 1) Xatos.py "MyApp_1986-1-1_Sean-teki-iPhone.crash" "Payload/MyApp.app/MyApp"
 2) Xatos.py "MyApp_1995-6-1_Noelani-teki-iPad.ips" "MyApp.app.dSYM"
        """)
    else:
        Xatos(sys_argv[1], sys_argv[2]).desymbolicate_file()


if __name__ == '__main__':
    main()

