# !/usr/sbin/python3
# -*- coding: UTF-8 -*-

import os
import argparse
import json
import re
import threading
import time
import functools
from collections import OrderedDict

import IPy
from cpkt.core import filelockv2 as f_lock
from cpkt.core import xpopen as xp
from cpkt.data import router_define as rd
from cpkt.icehelper import router_rpc as rr
from cpkt.core import xlogging

current_dir = os.path.split(os.path.realpath(__file__))[0]
config_path = os.path.join(current_dir, 'logging.config')
xlogging.set_logging_config(config_path)

_logger = xlogging.get_logger('firewall_helper')

LOWEST_VALID_PORT = 1
HIGHEST_VALID_PORT = 65535
PULL_PORT_RULES_INTERVAL = 30

TYPE_SINGLE_PORT = 0  # 端口类别-单个端口("22")
TYPE_PORT_GROUP = 1  # 端口类别-端口组("80,443,8000")
TYPE_PORT_RANGE = 2  # 端口类别-端口区间("445-500")

PORT_PROTOCOL_TCP = 'tcp'
PORT_PROTOCOL_UDP = 'udp'
PORT_PROTOCOL_DEFAULT = PORT_PROTOCOL_TCP
PORT_SUPPORT_PROTOCOL = (PORT_PROTOCOL_TCP, PORT_PROTOCOL_UDP)

SSH_PORT = "22"  # SSH连接端口
VNC_PORT = "20004,20005"  # VNC端口
VM_VNC_PORT = "6100-6611"  # 虚拟VNC端口
WEB_ACCESS_PORT = "80,8000,443"  # WEB访问端口
BACKUP_RESTORE_PORT = "20000-20002"  # 备份/恢复端口

AIO_PORTS_LIST = [
    SSH_PORT,
    BACKUP_RESTORE_PORT,
    WEB_ACCESS_PORT,
    VNC_PORT,
    VM_VNC_PORT
]

FIREWALL_CMD_LOCK_FILE = '/run/firewall_cmd_lock'
HISTORY_PORT_RULES_CACHE = '/etc/aio/nodes_port_conf_cache.json'

FIREWALL_IP_REGEX = re.compile(r'address="(.*?)".*?port="(.*?)".*?protocol="(.*?)"')


# functions


def file_locker(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        with f_lock.FileExLockV2(FIREWALL_CMD_LOCK_FILE):
            return func(*args, **kwargs)

    return wrapper


# classes


class PortRange(object):
    """端口区间类"""

    def __init__(self, low_port: (int, str), high_port: (int, str)):
        self.low_port = low_port if isinstance(low_port, int) else int(low_port)
        self.high_port = high_port if isinstance(high_port, int) else int(high_port)

    def has_overlap(self, _to):
        """若两个端口区间存在交集，则返回True"""
        assert isinstance(_to, PortRange)

        if _to.high_port > self.high_port:
            base, comparator = _to, self
        else:
            base, comparator = self, _to

        if base.low_port <= comparator.low_port <= base.high_port:
            return True
        if base.low_port <= comparator.high_port <= base.high_port:
            return True
        return False


class FireWallDHelper(object):
    """适用于CentOS7的防火墙配置类"""

    _inst = None
    _inst_locker = threading.Lock()

    @staticmethod
    def get_inst():
        with FireWallDHelper._inst_locker:
            if FireWallDHelper._inst is None:
                FireWallDHelper._inst = FireWallDHelper()
            return FireWallDHelper._inst

    @file_locker
    def update_port(self, all_rules: list, persistence=False):
        """更新端口规则

        :param persistence
            True为 更新持久化规则
            False为 更新当前规则

        :param all_rules 数据结构为
            [
                {
                    "type": "tcp",  端口类型tcp
                    "port": "22",   端口22需要更新
                    "allow": True,  允许访问
                    "ips": [],      允许所有ip
                },
                {
                    "type": "tcp",  端口类型tcp
                    "port": "445-500",  端口445-500之间的所有端口（含445，500端口）需要更新规则
                    "allow": False,     不允许访问
                    "ips": ["1.2.3.4-5.6.7.8"], 因为设置了不允许访问，该字段忽略，无意义
                },
                {
                    "type": "tcp",  端口类型tcp
                    "port": "80,443,8000",  端口80,443,8000需要更新规则
                    "allow": True,      允许访问
                    "ips": ["192.168.0.0/24", "172.16.16.0/24"],  允许访问的ip范围。
                        每个元素表示一个ip范围，所有的ip范围都可访问。
                },
                {
                    "type": "udp",  端口类型udp
                    "port": "53",   端口53需要更新
                    "allow": False, 不允许访问
                    "ips": [],      因为设置了不允许访问，该字段忽略，无意义
                },
            ]

        备注:
            1. 没有在入参中描述的端口，不变更已有规则
            2. 支持多进程并发调用，使用公共库中的文件锁保证互斥
            3. 不使用reload方法，防止当前规则被意外重置
        """
        try:
            _logger.info('all_rules {} persistence {}'.format(all_rules, persistence))
            self._update_port_logic(all_rules, persistence)
            return 0
        except (ValueError, OSError, Exception) as e:
            _logger.error("Error in update_port. Detail:{}".format(e), exc_info=True)
            return 1

    @file_locker
    def load_port(self, load_ports: list, persistence=False) -> list:
        """获取端口规则，仅获取指定的端口

        :param persistence
            True为 获取持久化规则
            False为 获取当前规则
        :param load_ports 需要获取的端口列表
            [
                {
                    "type": "tcp",  端口类型tcp
                    "port": "22",   端口22
                },
                {
                    "type": "udp",  端口类型udp
                    "port": "53",   端口53
                },
                {
                    "type": "tcp",  端口类型tcp
                    "port": "445-500",  端口445-500之间的所有端口（含445，500端口）
                },
                {
                    "type": "tcp",  端口类型tcp
                    "port": "80,443,8000",  端口80,443,8000
                },
            ]

        :return 返回列表

            [
                {
                    "type": "tcp",  端口类型tcp
                    "port": "22",   端口22需要更新
                    "allow": True,  允许访问
                    "ips": [],      允许所有ip
                },
                {
                    "type": "tcp",  端口类型tcp
                    "port": "445-500",  端口445-500之间的所有端口（含445，500端口）需要更新规则
                    "allow": False,     不允许访问
                },
                {
                    "type": "tcp",  端口类型tcp
                    "port": "80,443,8000",  端口80,443,8000需要更新规则
                    "allow": True,      允许访问
                    "ips": ["192.168.0.0/24", "172.16.16.0/24"],  允许访问的ip范围。
                        每个元素表示一个ip范围，所有的ip范围都可访问。
                },
                {
                    "type": "udp",  端口类型udp
                    "port": "53",   端口53需要更新
                    "allow": False, 不允许访问
                },
            ]

        """

        ret = list()

        # 所有已开放端口的防火墙规则信息
        all_rules = FireWallDHelper.prioritized_rules(persistence)  # type: OrderedDict

        for selected_port in load_ports:

            # `port` 可能出现的形式有`21113`(单个端口)、`21113-22224`(端口区间)、`80,443,8000`(端口组)
            validated_port = self._validated_port(selected_port['port'], all_rules=all_rules)
            validated_type = self._validated_protocol(selected_port['type'])
            if self.port_type(validated_port) in [TYPE_SINGLE_PORT, TYPE_PORT_RANGE]:
                ret.append(self._one_port_rule(selected_port, all_rules))

            else:
                # port_group_rules = [__one_port_rule({'type': validated_type, 'port': one_port}, all_rules)
                #                     for one_port in validated_port.split(',') if one_port]
                #
                # # 端口组中每一个端口号的富规则必须是一致的
                # if len(set(port_group_rules)) != 1:
                #     raise ValueError(
                #         "The rich rules for each port number in the port group must be consistent. rules:{}".format(
                #             port_group_rules
                #         ))

                last_type, last_ips, last_allow = None, list(), False
                for one_port in validated_port.split(','):
                    one_rule = self._one_port_rule({'type': validated_type, 'port': one_port}, all_rules)

                    if not one_port.strip():
                        continue
                    if last_type and (
                            last_type != one_rule['type'] or
                            last_ips != one_rule.get('ips', list()) or
                            last_allow != one_rule['allow']
                    ):
                        raise ValueError(
                            "The rich rules for each port number in the port group must be consistent. rules:{}".format(
                                one_rule
                            ))

                    last_type = one_rule['type']
                    last_allow = one_rule['allow']
                    last_ips = one_rule.get('ips', list())

                one_group_rule = dict()
                one_group_rule['type'] = last_type
                one_group_rule['allow'] = last_allow
                one_group_rule['ips'] = last_ips
                one_group_rule['port'] = validated_port
                ret.append(one_group_rule)
        return ret

    def query_all_port(self, persistence=False):
        """查询当前所有开放端口

        :return 返回列表

            [
                {
                    "type": "tcp",  端口类型tcp
                    "port": "22",   端口22需要更新
                    "allow": True,  允许访问
                    "ips": [],      允许所有ip
                },
                {
                    "type": "tcp",  端口类型tcp
                    "port": "445-500",  端口445-500之间的所有端口（含445，500端口）需要更新规则
                    "allow": False,     不允许访问
                },
                {
                    "type": "tcp",  端口类型tcp
                    "port": "80,443,8000",  端口80,443,8000需要更新规则
                    "allow": True,      允许访问
                    "ips": ["192.168.0.0/24", "172.16.16.0/24"],  允许访问的ip范围。
                        每个元素表示一个ip范围，所有的ip范围都可访问。
                },
                {
                    "type": "udp",  端口类型udp
                    "port": "53",   端口53需要更新
                    "allow": False, 不允许访问
                },
            ]
        """

        load_ports_arg = [{'type': PORT_PROTOCOL_DEFAULT, 'port': p} for p in AIO_PORTS_LIST]
        return self.load_port(load_ports_arg, persistence)

    def _update_port_logic(self, all_rules: list, persistence=False):
        for new_port_rule in all_rules:
            # 配置端口信息
            self._config_firewall_rule(
                self._validated_protocol(new_port_rule['type']),
                self._validated_port(new_port_rule['port']),
                [self._validated_ip(ip) for ip in new_port_rule.get('ips', list())],
                new_port_rule['allow'],
                persistence
            )
        else:
            # 配置成功
            return 1

    def _config_firewall_rule(self, validate_type: str,
                              validate_port: str, validate_ips: list,
                              open_port: bool, persistence=False):

        _logger.info(
            '_config_firewall_rule: type {} port {} ips {} open_port {} persistence {}'.format(
                validate_type, validate_port, validate_ips, open_port, persistence))

        if self.port_type(validate_port) == TYPE_PORT_GROUP:
            port_iter = validate_port.split(',')
        else:
            port_iter = [validate_port, ]

        for port in port_iter:
            # 开放端口，允许所有IP访问
            if open_port and not validate_ips:
                self._config_port_enable(validate_type, port, persistence)
            # 开放端口，但限制IP访问
            elif open_port and validate_ips:
                self._config_port_enable_and_limit_ips(validate_type, port, validate_ips, persistence)
            # 禁用端口，禁止所有IP访问
            elif not open_port:
                self._config_port_disable(validate_type, port, persistence)
            else:
                raise OSError(
                    "Invalid port operation. validate_type:{}, validate_port:{}, validate_ips:{}, open_port:{}".format(
                        validate_type,
                        port,
                        validate_ips,
                        open_port
                    ))

            #
            if port == SSH_PORT:
                remove_sshd_service_cmd = 'firewall-cmd --zone=public --remove-service=ssh'
                self._op_firewall_by_cmd(remove_sshd_service_cmd)

    def _config_port_enable(self, validate_type: str, validate_port: str, persistence=False):
        """开放端口，允许所有IP访问

        操作过程：
            1. 若待开放端口（validate_port）已存在于全局规则中，则不作任何操作，否则执行2
            2. 执行firewall-cmd --add-port=【validate_port】/tcp, 开放端口(将端口添加至全局规则中)
        """
        global_rules = self._list_ports()
        if validate_port in global_rules.keys() and \
                global_rules[validate_port]['type'] == validate_type:  # 端口号及端口协议均要匹配
            pass
        else:
            self._add_port(validate_port, validate_type, persistence)

    def _config_port_enable_and_limit_ips(self, validate_type, validate_port, validate_ips, persistence=False):
        """开放端口，但限制IP访问

        操作过程：

            前提：
            1.1 若待开放端口（validate_port）已存在于全局规则中，则先将validate_port从全局规则中移除

            过程：
            2.1. 若validate_port不存在于富规则（rich rules）中，则添加该端口至富规则，否则执行2.2
            2.2. 比较旧端口限制的IP集与validate_ips是否一致。若一致，则不作任何操作；若不一致，则先移除旧规则，再添加新规则
        """

        global_rules = self._list_ports()
        rich_rules = self._list_rich_rules()

        if validate_port in global_rules.keys() and \
                global_rules[validate_port]['type'] == validate_type:
            self._remove_port(validate_port, validate_type, persistence)

        unexisted_case_1 = validate_port in rich_rules.keys() and rich_rules[validate_port]['type'] != validate_type
        unexisted_case_2 = validate_port not in rich_rules.keys()
        if unexisted_case_1 or unexisted_case_2:
            for address in validate_ips:
                self._add_rich_rule(address, validate_port, validate_type, persistence)
            return

        existed_ips = rich_rules[validate_port]['ips']
        if set(existed_ips) != set(validate_ips):
            # 移除旧规则
            for address in existed_ips:
                self._del_rich_rule(address, validate_port, validate_type, persistence)
            # 添加新规则
            for address in validate_ips:
                self._add_rich_rule(address, validate_port, validate_type, persistence)

    def _config_port_disable(self, validate_type, validate_port, persistence=False):
        """禁用端口

        过程：
            1. 若validate_port在全局规则中，则移除；否则，执行2
            2. 若validate_port存在于富规则中，则移除已有富规则，否则不做任何操作
        """
        global_rules = self._list_ports()
        rich_rules = self._list_rich_rules()

        if validate_port in global_rules.keys() and \
                global_rules[validate_port]['type'] == validate_type:  # 端口号及端口协议均要匹配
            self._remove_port(validate_port, validate_type, persistence)

        if validate_port in rich_rules.keys() and \
                rich_rules[validate_port]['type'] == validate_type:
            for ip in rich_rules[validate_port].get('ips', list()):
                self._del_rich_rule(ip, validate_port, validate_type)

    @staticmethod
    def _validated_protocol(protocol: str) -> str:
        """验证端口协议的合法性

        :return: str
        """
        if protocol not in PORT_SUPPORT_PROTOCOL:
            raise ValueError(
                "The firewall's port access protocol can only be one of {}".format(PORT_SUPPORT_PROTOCOL))
        return protocol

    @staticmethod
    def _ip_family(address: str) -> int:
        """获取ip地址版本

        >>> IPy.IP('10.0.0.0/8').version()
        4
        >>> IPy.IP('::1').version()
        6
        """

        return IPy.IP(address).version()

    @staticmethod
    def _validated_ip(address: str) -> str:
        """验证IP的合法性

        :return: address
        """
        IPy.IP(address)
        return address

    @staticmethod
    def _validated_port(port: str, all_rules=None) -> str:
        """验证端口的合法性

        :remark:
            效验端口有效性的规则？
            1. 端口范围有效性，1-65535
            2. 在端口范围有交叠的情况下，要么完全相同，否则视为端口范围不合法
        :return: port
        """

        def __verify_port_in_valid_range(list_ports):
            """验证端口是否处于有效范围中
            """
            valid_port_iter = filter(lambda _p: LOWEST_VALID_PORT <= int(_p) <= HIGHEST_VALID_PORT, port_container)
            valid_port_num = len(list(valid_port_iter))
            if valid_port_num != len(list_ports):
                raise ValueError(
                    'Invalid `port`. The valid range of the port is [{}, {}], but `port` is {}'.format(
                        LOWEST_VALID_PORT,
                        HIGHEST_VALID_PORT,
                        port))

        def __verified_port_range():
            """验证端口区间的有效性并返回
            """
            nonlocal port_container, all_rules
            __verify_port_in_valid_range(port_container)

            # 校验区间的合法性，例如端口区间为"A-B"，则A必须小于B
            if len(port_container) != 2 or (len(port_container) == 2 and port_container[0] >= port_container[1]):
                raise ValueError('Invalid `port`. Port interval error, `port` is {}'.format(port))

            # 所有已开放端口的防火墙规则信息
            if not all_rules:
                all_rules = FireWallDHelper.prioritized_rules()  # type: OrderedDict

            # 效验端口区间是否存在交集
            if port not in all_rules.keys():
                new_port_interval = PortRange(*port_container)
                for port_range in filter(
                        lambda _p: FireWallDHelper.port_type(_p) == TYPE_PORT_RANGE, all_rules.keys()):
                    existed_port_interval = PortRange(*(port_range.split('-')))
                    if not new_port_interval.has_overlap(existed_port_interval):
                        continue

                    # 端口区间有交集
                    raise ValueError(
                        'In valid `port`. There must be no intersection between port intervals, `{}`&`{}`'.format(
                            port,
                            port_range
                        ))
            return port

        def __verified_port_list():
            """验证端口组的有效性并返回
            """
            nonlocal port_container
            __verify_port_in_valid_range(port_container)
            return port

        if FireWallDHelper.port_type(port) == TYPE_PORT_RANGE:
            port_container = tuple(port.split('-'))
            return __verified_port_range()
        elif FireWallDHelper.port_type(port) == TYPE_PORT_GROUP:
            port_container = tuple(port.split(','))
            return __verified_port_list()
        else:
            port_container = (port,)
            return __verified_port_list()

    @staticmethod
    def port_type(port: str) -> int:
        """获取端口的形式类别

        :return: int
        """
        if '-' in port:
            return TYPE_PORT_RANGE
        elif ',' in port:
            return TYPE_PORT_GROUP
        else:
            return TYPE_SINGLE_PORT

    @staticmethod
    def prioritized_rules(persistence=False):

        ret = OrderedDict()
        for k, v in FireWallDHelper._list_rich_rules(persistence).items():
            ret[k] = v
        for k, v in FireWallDHelper._list_ports(persistence).items():
            ret[k] = v

        return ret

    @staticmethod
    def _one_port_rule(_one_load_port, _existed_rules) -> dict:
        """
        :return:
        """
        port_, type_ = _one_load_port['port'], _one_load_port['type']
        if _existed_rules.get(port_) and _existed_rules[port_]['type'] != type_:
            raise ValueError(
                'Port `{}` connection protocol mismatch. Expect to get {}, Actually get {}.'.format(
                    port_,
                    type_,
                    _existed_rules[port_]['type']
                ))

        one_port_rule = {
            'type': type_,
            'port': port_,
            'allow': True if _existed_rules.get(port_) else False,
        }
        if _existed_rules.get(port_):
            one_port_rule['ips'] = _existed_rules[port_]['ips']
        return one_port_rule

    @staticmethod
    def _op_firewall_by_cmd(cmd: str):
        r, out, err = xp.execute_cmd(cmd)
        _logger.info('_op_firewall_by_cmd : {}. {}'.format(cmd, r))
        if r != 0:
            raise OSError('Failed to execute `cmd` because of {}'.format(err))
        return out

    @staticmethod
    def _list_ports(persistence=False) -> dict:
        """查询端口的全局访问规则

        :return: dict
                {
                    '22': {
                        'type': 'tcp',
                        'port': 22,
                        'allow': True,
                        'ips': [],
                    },
                    ...
                }
        """
        cmd = 'firewall-cmd {} --zone=public --list-ports'.format('--permanent' if persistence else '')
        ports_content = FireWallDHelper._op_firewall_by_cmd(cmd)

        ret = dict()
        for port_item in filter(
                lambda _p: PORT_PROTOCOL_UDP in _p or PORT_PROTOCOL_TCP in _p, ports_content.split()):
            port_no, port_type = port_item.split(r'/')
            ret[port_no] = {
                'type': port_type,
                'allow': True,
                'port': port_no,
                'ips': list()
            }

        return ret

    @staticmethod
    def _list_rich_rules(persistence=False) -> dict:
        """查询端口的访问富规则

        :return: dict
                {
                    '22': {
                        'type': 'tcp',
                        'port': 22,
                        'allow': True,
                        'ips': ['192.168.0.1/32', '192.168.0.1/32'],
                    },
                    ...
                }
        """
        cmd = 'firewall-cmd {} --zone=public --list-rich-rules'.format('--permanent' if persistence else '')

        ret = dict()
        for line in FireWallDHelper._op_firewall_by_cmd(cmd).splitlines():
            matcher = FIREWALL_IP_REGEX.search(line)
            if not matcher:
                continue
            rule_ip, rule_port, rule_type = matcher.groups()
            if not ret.get(rule_port):
                ret[rule_port] = {
                    'type': rule_type,
                    'ips': [rule_ip, ],
                    'port': rule_port,
                    'allow': True,
                }
            else:
                ret[rule_port]['ips'].append(rule_ip)

        return ret

    @staticmethod
    def _add_rich_rule(address: str, port: str, protocol: str = PORT_PROTOCOL_TCP, persistence=False):
        """配置防火墙 -添加某一端口的访问富规则(rich_rules)
        """
        FireWallDHelper._op_rich_rule('add', address, port, protocol, persistence)

    @staticmethod
    def _del_rich_rule(address: str, port: str, protocol: str = PORT_PROTOCOL_TCP, persistence=False):
        """配置防火墙 -移除某一端口的访问富规则(rich_rules)
        """
        FireWallDHelper._op_rich_rule('remove', address, port, protocol, persistence)

    @staticmethod
    def _op_rich_rule(op: str, address: str, port: str,
                      protocol: str = PORT_PROTOCOL_TCP,
                      persistence=False, need_validate=False):

        def __ip_family(_address):
            if FireWallDHelper._ip_family(_address) == 4:
                return 'ipv4'
            elif FireWallDHelper._ip_family(_address) == 6:
                return 'ipv6'
            else:
                raise ValueError('Only IPv4 and IPv6 are supported.')

        key_args = 'rule family="{}" source address={} port port="{}" protocol="{}" accept'.format(
            __ip_family(address),
            FireWallDHelper._validated_ip(address) if need_validate else address,
            FireWallDHelper._validated_port(port) if need_validate else port,
            FireWallDHelper._validated_protocol(protocol) if need_validate else protocol,
        )

        cmd = "firewall-cmd {} --zone=public --{}-rich-rule '{}'".format(
            '--permanent' if persistence else '',
            op,
            key_args)

        FireWallDHelper._op_firewall_by_cmd(cmd)
        _logger.info("[*] {} rich-rule success：port:{}, ip:{}, protocol:{}\n".format(op, port, address, protocol))

    @staticmethod
    def _add_port(port: str, protocol: str, persistence=False):
        """配置防火墙 -添加某一端口的全局访问规则(允许任意IP网段访问)
        """
        FireWallDHelper._op_global_rule('add', port, protocol, persistence)

    @staticmethod
    def _remove_port(port: str, protocol: str, persistence=False):
        """配置防火墙 -移除某一端口的全局访问规则(禁止任意IP网段访问)
        """
        FireWallDHelper._op_global_rule('remove', port, protocol, persistence)

    @staticmethod
    def _op_global_rule(op, port: str, protocol: str, persistence=False, need_validate=False):
        """配置防火墙 -配置全局访问规则
        """
        cmd = "firewall-cmd {} --zone=public --{}-port={}/{}".format(
            '--permanent' if persistence else '',
            op,
            FireWallDHelper._validated_port(port) if need_validate else port,
            protocol)

        FireWallDHelper._op_firewall_by_cmd(cmd)
        _logger.info("[*] {} global-rule success：port:{}, ip: all, protocol:{}\n".format(op, port, protocol))


class FireWallConfigPuller(threading.Thread):
    """定时获取端口规则
    """

    def __init__(self):
        super(FireWallConfigPuller, self).__init__(name='FireWallConfigPuller')
        self.cache = dict()

    def run(self):
        time.sleep(12)  # 等待其他组件加载完毕
        _logger.info("FireWallConfigPuller start...")
        while True:
            try:
                self.execute()
                time.sleep(PULL_PORT_RULES_INTERVAL)
            except Exception as e:
                _logger.error("Error in FireWallConfigPuller. e:{}".format(e), exc_info=True)

    def execute(self):
        new_rules = rr.rpc.op(rd.DASHBOARD_ROUTER_LOCATOR, 'ice_query_firewall_port_rules', {})

        # `ice_query_firewall_port_rules`远程调用返回值说明：
        # {
        #     'result': {
        #           'ssh_connect': {
        #             "type": "tcp", 端口类型tcp
        #             "port": "22",   端口22需要更新
        #             "allow": True,  允许访问
        #             "ips": [],      允许所有ip
        #           },
        #           'web_access': {
        #             "type": "tcp",  端口类型tcp
        #             "port": "80,443,8000",  端口80,443,8000需要更新规则
        #             "allow": True,      允许访问
        #             "ips": ["192.168.0.0/24", "172.16.16.0/24"],  允许访问的ip范围。
        #                 每个元素表示一个ip范围，所有的ip范围都可访问。
        #           }
        #           ...
        #     },
        # }
        need_reset_rules, full_rules = self._new_port_rules_for_update(new_rules)
        firewall_helper = FireWallDHelper.get_inst()

        # 当从节点上线后，若出现端口冲突，则用云平台设定的端口规则将冲突覆盖
        if not self.cache:
            ports_conflict_rule = self._conflict_ports(firewall_helper.prioritized_rules(), full_rules)
            _logger.info("ports_conflict_rule: {}".format(ports_conflict_rule))
            if ports_conflict_rule:
                firewall_helper.update_port(ports_conflict_rule, persistence=False)

        if need_reset_rules:
            firewall_helper.update_port(need_reset_rules, persistence=False)
            self.cache = full_rules

    def _new_port_rules_for_update(self, new_rules: dict):
        res = list()
        history_rules = dict()
        _cache = self.cache

        for k, _new in new_rules.items():
            new_rule = self._one_update_rule(_new)
            history_rules[k] = new_rule

            # 若没有历史规则，则应用`ice_query_firewall_port_rules`返回的所有端口规则
            if k not in _cache.keys():
                res.append(new_rule)
                continue

            # 若存在历史规则，则只应用当前端口规则与历史端口规则的差异部分
            if _cache[k]['type'] != new_rule['type'] or \
                    _cache[k]['port'] != new_rule['port'] or \
                    _cache[k]['allow'] != new_rule['allow'] or \
                    set(_cache[k].get('ips', [])) != set(new_rule['ips']):
                res.append(new_rule)

        return res, history_rules

    @staticmethod
    def _one_update_rule(rule: dict) -> dict:
        _new = dict()
        _new['type'] = rule['type']
        _new['port'] = rule['port']
        _new['allow'] = rule['allow']
        _new['ips'] = rule.get('ips', list())

        return _new

    @staticmethod
    def _conflict_ports(existed_rules: OrderedDict, ice_rules: dict) -> list:
        """返回存在端口冲突的规则

        在缓存的历史端口规则(服务启动成功后)为空且ice_rules的优先级高于existed_rules的前提下.
        假设防火墙预置临时规则中的端口集合为U1，ICE查询到的端口集合为U2，
        那什么情况认为端口存在冲突？

        1. U1与U2的交集不为空, 由于在此步骤后，会应用所有ice_rules，所以该情况不作处理
        2. 存在一个U1中的端口A（单个端口号）处于U2集合中端口B（端口区间）之间
        3. (未做支持)存在一个U1中的端口A（端口区间）及U2集合中端口B（端口区间），A与B存在区间重叠
        4. (未做支持)存在一个U2集合中端口B（单个端口号）处于U1集合中端口A(端口区间）之间
        """

        existed_ports_set = set(existed_rules.keys())
        ice_ports_set = set(
            [_r['port'] for _, _r in ice_rules.items() if _r.get('port')]
        )

        need_remove_rules = list()
        for _existed_p in existed_ports_set:
            for _ice_p in ice_ports_set:

                # 若存在一个U1中的端口A（单个端口号）处于U2集合中端口B（端口区间）之间，则禁用端口A
                if (FireWallDHelper.port_type(_existed_p) == TYPE_SINGLE_PORT and
                        FireWallDHelper.port_type(_ice_p) == TYPE_PORT_RANGE):

                    _ice_low_port, _ice_high_port = _ice_p.split('-')
                    if int(_ice_low_port) <= int(_existed_p) <= int(_ice_high_port):
                        one_remove_rule = dict()
                        one_remove_rule['type'] = PORT_PROTOCOL_DEFAULT
                        one_remove_rule['port'] = _existed_p
                        one_remove_rule['allow'] = False
                        need_remove_rules.append(one_remove_rule)

        return need_remove_rules


def run_as_script_support():
    """支持以脚本方式运行

    :return:
    """
    description = """{} 实现了通过执行Py脚本来达到配置防火墙规则的目的
    [注意]：
        1. 仅需要支持对 default-zone 的设置，不需要指定 zone
        2. 调试日志位置位于/var/log/firewalld_helper.log
        3. 端口参数不会发生变化，总是按照相同的组合进行查询与设置
            * 举例
              如果 查询的时候，传入的是`{{ "type": "tcp", "port": "445-500" }}`；
              那么 设置的时候也一定是传入`{{ "type": "tcp", "port": "445-500" }}`;
        4. 端口范围有效性，1-65535
        5. ip段有效性，内部使用的是IPy库检测
        6. 支持的操作系统为：
            * CentOS7
    """.format(__file__)

    op_update_help = """用于更新指定端口的富规则，仅支持指定json文件命令行入参
    该操作对应的json格式为：
        [
            {
                "type": "tcp",  // 端口类型tcp
                "port": "22",   // 端口22需要更新
                "allow": True,  // 允许访问
                "ips": [],      // 允许所有ip
            },
        ]
    举例：python3 firewalld.py --update=./update_port_rule.json
    """

    op_load_help = """用于查询指定端口的富规则，仅支持指定json文件命令行入参
    该操作对应的json格式为：
        [
            {
                "type": "tcp",  // 端口类型tcp
                "port": "22",   // 查询端口22
            },
        ]
    举例：python3 firewalld.py --load=./load_port_rule.json
    """

    op_all_help = """用于查询所有端口的富规则
    举例：python3 firewalld.py --all
    """

    def __parse_arg_value(arg_value) -> list:
        if os.path.isfile(arg_value):
            with open(arg_value, 'r') as f:
                return json.load(f)
        return json.loads(arg_value)

    def __op_query_all(_persistence):
        firewall_ins.query_all_port(_persistence)

    def __op_load_port(_persistence):
        firewall_ins.load_port(__parse_arg_value(args.load), _persistence)

    def __op_update_port(_persistence):
        firewall_ins.update_port(__parse_arg_value(args.update), _persistence)

    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-u', '--update', type=str, help=op_update_help)
    parser.add_argument('-l', '--load', type=str, help=op_load_help)
    parser.add_argument('-a', '--all', action="store_true", help=op_all_help)
    parser.add_argument('-p', '--permanent', action="store_true", help=op_all_help)
    args = parser.parse_args()

    firewall_ins = FireWallDHelper.get_inst()
    persistence = True if args.permanent else False

    if args.all is True:
        __op_query_all(persistence)
    elif args.load is not None:
        __op_load_port(persistence)
    elif args.update is not None:
        __op_update_port(persistence)
    else:
        raise ValueError('Error: Invalid options.')


if __name__ == '__main__':
    run_as_script_support()
