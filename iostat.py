# !/usr/local/python3.6/bin/python3.6
# -*- coding: utf-8 -*-

import argparse
import functools
import os
import platform
from datetime import datetime

import psutil

DISK_STAT_FILE = r'/proc/diskstats'


# functions


def convert_error_to_value(value):
    """将异常转换为自定义值
    """

    def wrapper(func):
        @functools.wraps(func)
        def handler(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except (ZeroDivisionError, Exception) as _:
                return value

        return handler

    return wrapper


def parse_args():
    """解析命令行参数

    :return(tuple): (设备名, 输出时间间隔)
    """

    def __fetch_key_args(_args: list) -> tuple:
        if len(args) > 2:
            raise argparse.ArgumentError(None, f'Invalid args: {args}')
        if not args:
            return None, 1
        if len(args) == 1:
            return (None, int(args[0])) if args[0].isdigit() else (args[0].split('/')[-1], 1)
        if len(args) == 2:
            if args[0].isdigit():
                _interval, _device = args
            else:
                _device, _interval = args
            return _device.split('/')[-1], int(_interval)

    parser = argparse.ArgumentParser(description='', formatter_class=argparse.RawTextHelpFormatter)
    _, args = parser.parse_known_args()
    return __fetch_key_args(args)


def format_sys_info() -> str:
    """系统信息的输出
    """
    _platform = platform.uname()
    return "{} {} ({}) 	{} 	{}	({} CPU){}".format(
        _platform.system,
        _platform.release,
        _platform.node,
        datetime.fromtimestamp(psutil.boot_time()).strftime("%d/%M/%Y"),
        _platform.machine,
        psutil.cpu_count(),
        os.linesep,
    )


def format_io_stats(io_stats: list) -> str:
    """io状态变化的输出

    iostat -xm 输出：
    Device: rrqm/s   wrqm/s  r/s     w/s     rMB/s    wMB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util
    fd0     0.00     0.00    0.00    0.00     0.00     0.00     0.00     0.00    0.00    0.00    0.00   0.00   0.00
    """
    stat_keys = ('Device', 'rrqm/s', 'wrqm/s', 'r/s', 'w/s', 'rMB/s', 'wMB/s',
                 'avgrq-sz', 'avgqu-sz', 'await', 'r_await', 'w_await', 'svctm', '%util')

    io_desc = "{}:         {}   {}     {}     {}    {}    {} {} {}   {} {} {}  {}  {}".format(*stat_keys)
    f = ("{:<11}{:>11.2f}{:>9.2f}{:>8.2f}{:>8.2f}{:>9.2f}{:>9.2f}{:>9.2f}{:>9.2f}{:>8.2f}{:>8.2f}{:>8.2f}{:>7.2f}{"
         ":>7.2f} ")

    lines = [io_desc, ]
    for one_device_stat in io_stats:
        one_device_vals = [one_device_stat[key] for key in stat_keys]
        lines.append(f.format(*one_device_vals))
    lines.append(os.linesep)

    return os.linesep.join(lines)


def format_cpu_stat(cpu_stat) -> str:
    """
    iostat -xm 输出：
    avg-cpu:  %user   %nice %system %iowait  %steal   %idle
              16.88    0.00    4.53    0.00    0.00   78.59
    """
    desc = "avg-cpu:  %user   %nice %system %iowait  %steal   %idle"
    val = "       {:>8.2f}{:>8.2f}{:>8.2f}{:>8.2f}{:>8.2f}{:>8.2f}".format(
        cpu_stat.user,
        cpu_stat.nice,
        cpu_stat.system,
        cpu_stat.iowait,
        cpu_stat.steal,
        cpu_stat.idle)
    return f"{desc}{os.linesep}{val}{os.linesep}"


# classes


class IOStat(object):
    """iostat工具

    数据源自：/proc/diskstats文件
    """

    class __DiskStat(object):

        def __init__(self, device, rd_ios, wr_ios, rd_merges, wr_merges, rd_sectors, wr_sectors,
                     rd_ticks, wr_ticks, in_flight, io_ticks, time_in_queue):
            """
            :param device: 设备名称
            :param rd_ios: 读操作的次数
            :param wr_ios: 写完成次数
            :param rd_merges: 合并读次数
            :param wr_merges: 合并写次数
            :param rd_sectors: 读扇区次数
            :param wr_sectors: 写扇区次数
            :param rd_ticks: 读操作花费的毫秒数
            :param wr_ticks: 写操作花费的毫秒数
            :param in_flight: 当前未完成的I/O数量
            :param io_ticks: 该设备用于处理I/O的自然时间(wall-clock time)
            :param time_in_queue: 对字段io_ticks的加权值
            """
            self.device = device
            self.rd_ios = rd_ios
            self.wr_ios = wr_ios
            self.rd_merges = rd_merges
            self.wr_merges = wr_merges
            self.rd_sectors = rd_sectors
            self.wr_sectors = wr_sectors
            self.rd_ticks = rd_ticks
            self.wr_ticks = wr_ticks
            self.in_flight = in_flight
            self.io_ticks = io_ticks
            self.time_in_queue = time_in_queue

    def __init__(self, device: str):
        """
        :param device: IO设备的文件路径
        """
        self._device = device
        self._stat_file = DISK_STAT_FILE

    @staticmethod
    def calc_io_stat(before_stat, after_stat, delta_secs) -> dict:
        """计算IO变化

        :param before_stat: __DiskStat
        :param after_stat: __DiskStat
        :param delta_secs: int
        :return: dict
        """

        @convert_error_to_value(0)
        def __div(a, b):
            return a / b

        x, y = before_stat, after_stat
        delta_rd_ios = y.rd_ios - x.rd_ios
        delta_wr_ios = y.wr_ios - x.wr_ios
        delta_rd_ticks = y.rd_ticks - x.rd_ticks
        delta_wr_ticks = y.wr_ticks - x.wr_ticks
        delta_io_ticks = y.io_ticks - x.io_ticks
        delta_rd_merges = y.rd_merges - x.rd_merges
        delta_wr_merges = y.wr_merges - x.wr_merges
        delta_rd_sectors = y.rd_sectors - x.rd_sectors
        delta_wr_sectors = y.wr_sectors - x.wr_sectors
        delta_time_in_queue = y.time_in_queue - x.time_in_queue

        io_stat = dict()
        io_stat['Device'] = x.device
        io_stat['r/s'] = __div(delta_rd_ios, delta_secs)
        io_stat['w/s'] = __div(delta_wr_ios, delta_secs)
        io_stat['svctm'] = __div(delta_io_ticks, delta_wr_ios + delta_rd_ios)
        io_stat['%util'] = __div(delta_io_ticks * 100, delta_secs * 1000)
        io_stat['rMB/s'] = __div(delta_rd_sectors * 512 / 1024 ** 2, delta_secs)
        io_stat['wMB/s'] = __div(delta_wr_sectors * 512 / 1024 ** 2, delta_secs)
        io_stat['await'] = __div(delta_wr_ticks + delta_rd_ticks, delta_wr_ios + delta_rd_ios)
        io_stat['rrqm/s'] = __div(delta_rd_merges, delta_secs)
        io_stat['wrqm/s'] = __div(delta_wr_merges, delta_secs)
        io_stat['r_await'] = __div(delta_rd_ticks, delta_rd_ios)
        io_stat['w_await'] = __div(delta_wr_ticks, delta_wr_ios)
        io_stat['avgrq-sz'] = __div(delta_wr_sectors + delta_rd_sectors, delta_wr_ios + delta_rd_ios)
        io_stat['avgqu-sz'] = __div(delta_time_in_queue, delta_secs * 1000)
        return io_stat

    def read_disk_stats(self) -> list:
        """从/proc/diskstats读取IO统计数据

        规则：
        当device为None时，显示所有IO设备的IO实时状态
        当device不为None时，仅显示指定IO设备的IO实时状态
        """
        ret = list()
        with open(self._stat_file, 'r') as fp:
            for obj in self.gen_disk_stat_obj(fp):
                ret.append(obj)

        return ret

    def gen_disk_stat_obj(self, fp):
        last_device = None

        for one_line in fp:
            disk_stats_14 = one_line.split()
            disk_stats_11 = [int(i) for i in disk_stats_14[-11:]]
            current_device = disk_stats_14[2]

            # 是否是磁盘分区
            is_partition = isinstance(last_device, str) and current_device.replace(last_device, '').isdigit()
            # 是否设备名不匹配
            is_device_not_match = self._device and self._device != current_device
            # 是否设备的IO数据统计始终为0
            is_always_no_io = not self._device and sum(disk_stats_11) == 0

            if not (is_partition or is_device_not_match or is_always_no_io):
                last_device = current_device

                """
                cat /proc/diskstats 返回结果（部分IO设备）如下：
                ...
                8      48 sdd  86836  2603 5637720 787051 683987 81501  25350024 9149088  0 7047656 9935707
                8      16 sdb  72887  19   2796376 129740 413023 21850  11101744 812381   0 794474  939986
                8       0 sda  188910 74   9125612 516010 880337 160059 65709762 12664851 0 2147442 13052911
                8       1 sda1 95140  0    1173216 98018  0      0      0        0        0 77025   97870
                ...

                在上述输出中，每一个单行以空格划分为了14个域：
                0       1 2    3      4    5       6      7      8      9        10       11 12     13
                前3个数据域分别表示主设备号、次设备号、设备名称，后11个数据域代表的含义如下：
                0 ：读完成次数
                1 ：合并读完成次数
                2 ：读扇区的次数
                3 ：读花费的毫秒数
                4 ：写完成次数
                5 ：合并写完成次数
                6 ：写扇区次数
                7 ：写操作花费的毫秒数
                8 ：正在处理的输入/输出请求数
                9 ：输入/输出操作花费的毫秒数
                10：输入/输出操作花费的加权毫秒数
                """
                yield self.__DiskStat(
                    device=disk_stats_14[2],
                    rd_ios=disk_stats_11[0],
                    wr_ios=disk_stats_11[4],
                    io_ticks=disk_stats_11[9],
                    rd_ticks=disk_stats_11[3],
                    wr_ticks=disk_stats_11[7],
                    rd_merges=disk_stats_11[1],
                    wr_merges=disk_stats_11[5],
                    in_flight=disk_stats_11[8],
                    rd_sectors=disk_stats_11[2],
                    wr_sectors=disk_stats_11[6],
                    time_in_queue=disk_stats_11[10],
                )


def main():
    """主流程逻辑

    1. 解析命令行参数得到设备(device)及间隔输出时间(interval)
    2. 循环：
        2.1 第一次采样（从/proc/diskstats读取IO统计数据）
        2.2 等待interval秒
        2.3 第二次采样从（/proc/diskstats读取IO统计数据）
        2.4 根据两次得到的数据结果，计算得到IO变化
        2.5 输出IO变化

    :return: None
    """
    device, interval = parse_args()
    _io = IOStat(device)

    print(format_sys_info())
    while True:
        # 两次采样
        before_stats = _io.read_disk_stats()
        cpu_stat = psutil.cpu_times_percent(interval=interval)  # sleep `interval` seconds
        after_stats = _io.read_disk_stats()

        # 计算
        assert len(before_stats) == len(after_stats)
        io_stats = [_io.calc_io_stat(x, y, interval) for x, y in zip(before_stats, after_stats)]

        # 格式化输出
        cpu_stat_string = format_cpu_stat(cpu_stat)
        io_stat_string = format_io_stats(io_stats)
        current_output = '{}\n{}'.format(cpu_stat_string, io_stat_string)
        print(current_output)


if __name__ == '__main__':
    main()
