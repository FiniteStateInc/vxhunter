# coding=utf-8
import logging
import re
import struct
from vxhunter_utility.ba import BAFinder

function_name_key_words = ['bzero', 'usrInit', 'bfill']

need_create_function = [0x04, 0x05]


class VxTarget(object):
    def __init__(self, firmware_path, firmware, vx_version=5, big_endian=False, word_size=4, logger=None):
        """
        :param firmware: data of firmware
        :param vx_version: 5 = VxWorks 5.x; 6= VxWorks 6.x
        :param big_endian: True = big endian; False = little endian
        :param logger: logger for the target (default: None)
        """
        self.big_endian = big_endian
        self._vx_version = vx_version
        self.symbol_table_start = None
        self.symbol_table_end = None
        self._string_table = []
        self._symbol_table = []
        self.symbols = []
        self.load_address = None
        self._firmware = firmware
        self._has_symbol = None
        if self._vx_version == 5:
            self._symbol_interval = 16
        elif self._vx_version == 6:
            self._symbol_interval = 20

        if logger is None:
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(logging.INFO)
            consolehandler = logging.StreamHandler()
            console_format = logging.Formatter('[%(levelname)-8s][%(module)s.%(funcName)s] %(message)s')
            consolehandler.setFormatter(console_format)
            self.logger.addHandler(consolehandler)
        else:
            self.logger = logger

        endy_str = ['<', '>'][int(big_endian)]
        ba = BAFinder(firmware_path, firmware, endy_str=endy_str, wordsize=word_size)

        if not ba.is_base_addr_good():
            self.logger.error('Could not find valid base address. Aborting')
            exit()

        self.symbols = ba.get_symbol_table()
        self.load_address = ba.base_addr

        if len(self.symbols) >= 2:
            self.symbol_table_start = self.symbols[0]['offset']
            self.symbol_table_end = self.symbols[-1]['offset']


    def cleanup(self):
        """ Clean up variables.

        :return:
        """
        self.big_endian = False
        self.symbol_table_start = None
        self.symbol_table_end = None
        self._string_table = []
        self._symbol_table = []
        self.load_address = None
        self._has_symbol = None


    def get_symbols(self):
        return self.symbols
