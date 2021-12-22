# !/usr/local/python3.6/bin/python3.6
# -*- coding: utf-8 -*-

import argparse
import struct
import os


def hex_out(binary: bytes, size=2) -> str:
    assert size in [1, 2], 'Invalid size'

    contents = list()
    for i in range(0, len(binary), size):
        flag = 'B' if size == 1 else 'H'
        packed_binary = struct.pack(f'{flag}', int(binary[i: i + size].hex(), 16))
        contents.append(packed_binary.hex())
    return ' '.join(contents)


class HexDump(object):
    """转码查看工具"""

    default_blk_size = 16

    def __init__(self, target_file: str, offset: int, limit_len: int, is_standard: bool = False):
        """
        :param target_file: 目标文件
        :param offset: 从偏移量开始输出
        :param limit_len: 限制输出的字节数, 若为-1表示不受限制
        :param is_standard: 如果为True, 则输出规范的十六进制和ASCII码
        """
        self.target_fp = open(target_file, 'rb')
        self.offset = offset
        self.is_standard = is_standard
        self.limit_length = limit_len

        # 暂存的转码过程中最近一次输出
        self.last_line = None
        # 暂存的转码过程中最近一次输出是否隐藏的标志
        self.last_visible_flg = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        _ = exc_type
        _ = exc_val
        _ = exc_tb
        self.target_fp.close()

    def pack(self):
        """转码"""
        self.target_fp.seek(self.offset, os.SEEK_SET)
        total_read_byte = 0
        stop_read_flg = False
        while True:
            block_bytes = self.target_fp.read(self.default_blk_size)
            total_read_byte += len(block_bytes)

            if not block_bytes or stop_read_flg:  # 格式化字节数达到限制或文件已读取完毕
                break

            valid_block = block_bytes
            if self.limit_length != -1 and total_read_byte > self.limit_length:
                valid_block = block_bytes[:self.limit_length - self.offset]
                stop_read_flg = True

            self.__output_logic(valid_block)  # 处理输出
            self.offset += len(valid_block)

        print(f'{self.offset:0{8}x}')

    def __output_logic(self, one_line_bytes):
        size = 1 if self.is_standard else 2
        hexlify_string = hex_out(one_line_bytes, size)

        current_line = self.__combine_one_line_info(
            f'{self.offset:0{8}x}',  # 偏移量
            hexlify_string,  # 转码结果
            self.__ascii_byte_display(one_line_bytes)  # 预览数据（仅ascii）
        )

        if not current_line.strip():
            return

        if self.last_line != hexlify_string:
            print(current_line)
            self.last_visible_flg = False
            self.last_line = hexlify_string
        else:
            if not self.last_visible_flg:  # 隐藏相同行
                print('*')
            self.last_visible_flg = True

    @staticmethod
    def __ascii_byte_display(_bytes_data: bytes) -> str:
        """输出_bytes_data中的ASCII码字符(0X20-0X7E)

        :remark: 非ASCII码使用`.`替换
        """
        one_line_list = list()
        for one_byte in _bytes_data:
            _c = '.'
            if 0x20 <= one_byte <= 0x7E:
                _c = chr(one_byte)
            one_line_list.append(_c)

        return ''.join(one_line_list)

    def __combine_one_line_info(self, offset_part, packed_part, readable_part):
        if not offset_part.strip() or not packed_part.strip():
            return

        common_parts = f"{offset_part}  {packed_part:<48}"
        one_line = common_parts
        if self.is_standard:
            one_line = f'{common_parts}  |{readable_part:<16}|'

        return one_line


def parse_args() -> tuple:
    """解析命令行参数

    :return(tuple):
    (目标文件路径, 偏移量, 限制输出的字节数, 是否输出规范的十六进制和ASCII码)
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', type=int, default=[0], nargs=1, help='从偏移量开始输出')
    parser.add_argument('-n', type=int, default=[-1], nargs=1, help='只格式化输入文件的前N个字节')
    parser.add_argument('-C', action='store_true', help='输出规范的十六进制和ASCII码')
    namespace, file_list = parser.parse_known_args()

    arg_file = file_list[0]
    arg_offset = namespace.s[0]
    arg_limit_len = namespace.n[0]
    arg_standard_mod = namespace.C
    return arg_file, arg_offset, arg_limit_len, arg_standard_mod


def script_main():
    args = parse_args()
    with HexDump(*args) as hd:
        hd.pack()


if __name__ == '__main__':
    script_main()
