# !/usr/local/python3.6/bin/python3.6
# -*- coding: utf-8 -*-

import argparse
import datetime
import os
import sys
from multiprocessing import JoinableQueue, Process

TIME_FORMAT_STR_A = '%Y-%m-%d %H:%M:%S,%f'  # e: 2020-06-23 08:18:40,004
TIME_FORMAT_STR_B = '%Y/%m/%d_%H:%M:%S_%f'  # e: 2020/04/17_16:01:19_938
TIME_FORMAT_STR_STANDARD = '%Y-%m-%d %H:%M:%S'


def enum_log_files(_dir: str):
    for root, dirs, files in os.walk(_dir):
        for f_name in files:
            if '.log' in f_name:
                yield os.path.join(root, f_name)


def query_final_log_time(file: str, block_size: int = 8192) -> tuple:
    """查询日志文件的最后一条日志的记录时间及其时间格式串
    若在文件的最后block_size大小的日志中，未匹配到日志时间，则返回(None, None)

    :return tuple: (datetime, datetime_format)
    """
    with open(file, 'rb') as fp:
        fp.seek(0, os.SEEK_END)
        file_size = fp.tell()
        fp.seek(file_size - min(file_size, block_size), os.SEEK_SET)

        last_blk_data = fp.read(block_size)
        if not last_blk_data:
            return None, None

        lines = last_blk_data.splitlines()
        for _l in lines[::-1]:
            _datetime, _date_format = convert_string_to_datetime(_l.decode('utf-8', 'ignore')[:23])  # 日志时间长度为23
            if not _datetime:
                continue
            return _datetime, _date_format

    return None, None


def convert_string_to_datetime(date_string: str, _format: str = None) -> tuple:
    """转换日期字符串为日期datetime类型并返回

    :param date_string: 日期字符串
    :param _format: 指定时间的格式化字符串，若为None，则尝试匹配所有
    :return tuple: (datetime, datetime_format)
    """

    def __strptime(date_format):
        nonlocal _format
        try:
            ret_date = datetime.datetime.strptime(date_string, date_format)
            _format = date_format
            return ret_date
        except ValueError:
            _format = None
            return None

    if _format is None:
        return __strptime(TIME_FORMAT_STR_B) or \
               __strptime(TIME_FORMAT_STR_A) or \
               __strptime(TIME_FORMAT_STR_STANDARD), _format
    else:
        return __strptime(_format), _format


def output_cache_2_file_and_stdout(path: str, content: str):
    print(content)
    with open(path, 'w') as fp:
        fp.write(content)


class ArgsParser(object):

    @staticmethod
    def fetch_parse_args() -> tuple:
        """解析命令行参数

        :return tuple: (搜素时间, 时间跨度, 工作进程数, 日志目录)
        """
        parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
        _, other_args = parser.parse_known_args()

        arg_datetime, arg_interval = ArgsParser._fetch_key_args(other_args)
        arg_dir = os.path.dirname(os.path.abspath(__file__))
        arg_process_num = 2

        return arg_datetime, arg_interval, arg_process_num, arg_dir

    @staticmethod
    def _fetch_key_args(other_args: list):
        if len(other_args) not in [2, 3]:
            raise argparse.ArgumentError(None, f'Invalid args `{other_args}`')
        arg_date, arg_time, arg_interval = '', '', 0

        for arg in other_args:
            try:
                arg_interval = int(arg)
            except ValueError as _:
                if '-' in arg:
                    arg_date = arg
                    continue
                if ':' in arg:
                    arg_time = arg
                    continue

        assert isinstance(arg_interval, int)
        return convert_string_to_datetime(f'{arg_date} {arg_time}')[0], arg_interval


class LogGrep(object):

    def __init__(self, file: str, search_datetime: datetime.datetime, interval: int, format_: str = None):
        """
        :param file: 日志文件路径
        :param format_: 时间格式化字符串
        :param search_datetime: 搜索时间
        :param interval: 搜素日志记录的前后时间跨度
        """
        self._file = file
        self._date_format = format_
        self._search_datetime_low = search_datetime + datetime.timedelta(seconds=-interval)
        self._search_datetime_high = search_datetime + datetime.timedelta(seconds=interval)

    def grep(self):
        logs_container = list()
        with open(self._file, 'r', encoding='utf-8', errors='ignore') as fp:
            self._grep_logic(fp, logs_container)
        print(f'Grep {self._file} success ..')
        return logs_container

    def _grep_logic(self, fp, result_container: list):
        last_contents = list()
        last_log_datetime = None
        for line in fp:

            cur_log_datetime, _format = convert_string_to_datetime(line[:23], self._date_format)  # 日志时间的固定长度为23
            if not cur_log_datetime:
                if last_log_datetime:
                    last_contents.append(line)
                continue

            assert cur_log_datetime is not None
            if cur_log_datetime > self._search_datetime_high:
                break

            if not self._date_format:
                self._date_format = _format
            # 已匹配到时间，且在查找时间段之间，则存储历史日志记录
            if self.is_valid(cur_log_datetime):
                if last_log_datetime:
                    self.collect_log(fp.name, last_log_datetime, last_contents, result_container)

                last_log_datetime = cur_log_datetime
                last_contents.append(line)

        # 处理最后一条日志记录
        if last_log_datetime:
            self.collect_log(fp.name, last_log_datetime, last_contents, result_container)

    def is_valid(self, log_datetime: datetime.datetime):
        return self._search_datetime_low <= log_datetime <= self._search_datetime_high

    @staticmethod
    def collect_log(log_file_name, log_datetime, one_log_records, result_container: list):
        """收集日志"""
        fire_dir, file_name = os.path.split(log_file_name)
        one_filter_result = dict()
        one_filter_result['file_name'] = file_name
        one_filter_result['log_detail'] = "[{}]: {}".format(file_name, ''.join(one_log_records).rstrip())
        one_filter_result['unix_timestamp'] = log_datetime
        result_container.append(one_filter_result)
        one_log_records.clear()


def work(in_queue: JoinableQueue, out_queue: JoinableQueue, search_datetime, interval):
    """工作程

    :param in_queue: 待处理的任务队列
    :param out_queue: 处理成功后的结果返回队列
    :param search_datetime: 指定的搜索时间
    :param interval: 日志时间的前后跨度
    :return: None
    """
    while True:
        try:
            log_file = in_queue.get()
            grep_tool = LogGrep(log_file, search_datetime, interval)
            out_queue.put(grep_tool.grep())
        except Exception as e:
            sys.stderr.write('Error: {}\n'.format(e))
        finally:
            in_queue.task_done()


def script_main():
    """主流程逻辑

    1. 解析命令行参数
    2. 初始化两个队列，一个用于生产待处理的日志文件（log_file_q），另一个用于存取每一个日志文件的过滤结果（grep_ret_q）
    3. 预启N个工作进程
    4. 主进程枚举日志文件，将其压入log_file_q，让工作进程处理，工作进程将处理结果回压至grep_ret_q
    5. 当所有工作进程处理完所有的日志文件后，聚合grep_ret_q中过滤结果并格式化输出
    :return: None
    """
    log_file_q = JoinableQueue()
    grep_ret_q = JoinableQueue()

    logs_cache = list()
    arg_datetime, arg_interval, arg_process_num, arg_dir = ArgsParser.fetch_parse_args()
    assert isinstance(arg_datetime, datetime.datetime)

    for i in range(arg_process_num):
        p = Process(target=work, args=(log_file_q, grep_ret_q, arg_datetime, arg_interval), daemon=True)
        p.start()

    for log_file in enum_log_files(arg_dir):
        # 预读文件的最后一次日志记录时间，若其在查找时间段之后，则跳过该文件
        final_log_datetime, _ = query_final_log_time(log_file)
        if final_log_datetime and final_log_datetime < arg_datetime + datetime.timedelta(seconds=-arg_interval):
            print(f'[*] Skip to grep file {log_file}')
            continue

        log_file_q.put(log_file)

    log_file_q.join()  # wait until all task done

    while not grep_ret_q.empty():
        logs_cache.extend(grep_ret_q.get())

    sorted_logs = sorted(logs_cache, key=lambda _l: (_l['unix_timestamp'], _l['file_name']))
    output = '\n'.join(map(lambda _i: _i['log_detail'], sorted_logs))
    output_cache_2_file_and_stdout('./_result.log', output)


if __name__ == '__main__':
    script_main()

    """
    example: 查询2020-06-17 11:51:56前后三秒的所有日志
    
    $ python3.6 lgrep.py 2020-06-17 11:51:56 3
    """
