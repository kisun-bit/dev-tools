import json
import logging
import os
import re
import shlex
import subprocess
import sys

# create logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# create console handler and set level to debug
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)

# create `formatter`
formatter = logging.Formatter('%(asctime)s - %(thread)d - %(name)s - %(levelname)s - %(message)s')

# add `formatter` to `handler`
handler.setFormatter(formatter)

# add `handler` to  `logger`
logger.addHandler(handler)


def is_ignore_device(devname):
    if not devname.startswith("/dev/"):
        full = os.path.join("/dev", devname)
    else:
        full = devname

    ignores = ["/dev/sr", "/dev/fd", "/dev/loop"]

    for i in ignores:
        if full.startswith(i):
            return True

    return False


def run_cmd_line(cmd_line):
    try:
        ret_lines = []
        p = subprocess.Popen(shlex.split(cmd_line), stdout=subprocess.PIPE, universal_newlines=True)
        stdout, _ = p.communicate()
        for line in stdout.splitlines():
            ret_lines.append(line.rstrip())
        return p.returncode, ret_lines
    except Exception as e:
        log_msg('run_cmd_line error: {0} {1}'.format(cmd_line, e))
        return -1, []


def log_msg(msg):
    logger.info(msg)


def get_one_alias(alias_path):
    log_msg("[get_one_alias] alias_path=" + alias_path)
    alias_items = list()
    dir_files = os.listdir(alias_path)
    for one_file in dir_files:
        log_msg("[get_one_alias] one_file=" + one_file)
        join_path = os.path.join(alias_path, one_file)
        if os.path.islink(join_path):
            target_name = os.readlink(join_path)
            join_target = os.path.join(alias_path, target_name)
            normal_target = os.path.normpath(join_target)
        else:
            normal_target = ""

        one_item = {
            "name": one_file,
            "target": normal_target
        }

        alias_items.append(one_item)

    return alias_items


def try_get_disk_alias(root_path):
    log_msg("[try_get_disk_alias] root_path=" + root_path)
    alias_data = list()
    dir_files = os.listdir(root_path)
    for one_file in dir_files:
        log_msg("[try_get_disk_alias] one_file=" + one_file)
        full_path = os.path.join(root_path, one_file)
        alias_items = get_one_alias(full_path)

        one_alias = {
            "alias_type": one_file,
            "alias_items": alias_items
        }

        alias_data.append(one_alias)

    return alias_data


def _get_sub_str_from_line_str(sub_mode, line_str):
    m = re.findall(pattern=sub_mode, string=line_str)
    return m[0] if m else None


def get_dev_name_uuid(dev_name):
    if is_ignore_device(dev_name):
        log_msg("[get_dev_name_uuid] ignore dev_name={}".format(dev_name))
        return None

    cmd = 'blkid {0}'.format(dev_name)
    code, lines = run_cmd_line(cmd)
    if code == 0:
        for line in lines:
            uuid_info = _get_sub_str_from_line_str(r'\s+UUID="\S+"\s*', line)
            if uuid_info:
                return uuid_info.strip().split('=')[-1].strip('"')

    log_msg('run_cmd_line: {0}. result: {1} {2}'.format(cmd, code, lines))
    return None


def _get_dev_name(line):
    fields = line.rstrip().split()
    if len(fields) != 4:
        return None
    if not fields[0].isdigit():
        return None
    if fields[0] == '253':
        return None

    dev_name = '/dev/{}'.format(fields[-1])

    if is_ignore_device(dev_name):
        log_msg("[_get_dev_name] ignore dev_name={}".format(dev_name))
        return None

    code, lines = run_cmd_line(r'blkid -s TYPE {}'.format(dev_name))
    if code != 0 or len(lines) != 1 or 'TYPE' not in lines[0]:
        return None

    type_info = lines[0].split('TYPE')[-1]
    return dev_name if 'swap' not in type_info else None


def get_dev_names_by_cat_proc_partitions():
    dev_names = []
    code, lines = run_cmd_line(r'cat /proc/partitions')
    if code != 0 or len(lines) == 0:
        return dev_names

    for line in lines:
        dev_name = _get_dev_name(line)
        if dev_name:
            dev_names.append(dev_name)

    return dev_names


def append_blkid_type_to_alias_list(alias_list):
    by_path = list(filter(lambda item: item['alias_type'] == 'by-path', alias_list))
    if len(by_path) == 0:
        dev_names = get_dev_names_by_cat_proc_partitions()
    else:
        by_path = by_path[0]
        dev_names = [item['target'] for item in by_path['alias_items']]

    log_msg('get all dev names: {0}'.format(dev_names))
    alias_items = []
    for dev_name in dev_names:
        uuid = get_dev_name_uuid(dev_name)
        if uuid:
            alias_items.append({'name': uuid, 'target': dev_name})

    alias_list.append({'alias_type': 'by-blkid', 'alias_items': alias_items})


def get_one_dev(line):
    if line.find("#blocks") > 0:
        return None

    items = line.split()
    if len(items) != 4:
        return None

    return "/dev/{}".format(items[3])


def get_blk_dev_id():
    cmd = r'cat /proc/partitions'
    code, lines = run_cmd_line(cmd)
    if code != 0:
        log_msg("[get_blk_dev_id] run_cmd_line cmd={}, code={}".format(cmd, code))
        return code, None

    blks = list()
    for i in lines:
        dev = get_one_dev(i)
        if not dev:
            continue

        log_msg("[get_blk_dev_id] dev={}".format(dev))
        if is_ignore_device(dev):
            log_msg("[get_blk_dev_id] ignore dev_name={}".format(dev))
            continue

        code, outputs = run_cmd_line(r'blkid {}'.format(dev))
        log_msg("[get_blk_dev_id] outputs={}".format("\n".join(outputs)))

        if code != 0:
            continue

        log_msg("[get_blk_dev_id] outputs={}".format("\n".join(outputs)))
        blks += outputs

    log_msg("[get_blk_dev_id] blks:\n{}\n".format("\n".join(blks)))
    return 0, blks


def append_swap_label_uuid_to_alias_list(alias_list):
    uuid_items, label_items = list(), list()
    # code, lines = run_cmd_line(r'blkid')
    code, lines = get_blk_dev_id()
    if code == 0 and lines:
        for line in lines:
            if r'TYPE="swap"' not in line:
                continue
            uuid_info = _get_sub_str_from_line_str(r'\s+UUID="\S+"\s*', line)
            label_info = _get_sub_str_from_line_str(r'\s+LABEL="\S+"\s*', line)
            dev_name = line.split(':')[0]
            if uuid_info:
                swap_uuid = uuid_info.strip().split('=')[-1].strip('"')
                uuid_items.append({'name': swap_uuid, 'target': dev_name})
            if label_info:
                swap_label = label_info.strip().split('=')[-1].strip('"')
                label_items.append({'name': swap_label, 'target': dev_name})

    alias_list.append({'alias_type': 'by-swap-uuid', 'alias_items': uuid_items})
    alias_list.append({'alias_type': 'by-swap-label', 'alias_items': label_items})


def get_disk_alias():
    try:
        root_disk = '/dev/disk'
        alias = try_get_disk_alias(root_disk)
        append_blkid_type_to_alias_list(alias)
        append_swap_label_uuid_to_alias_list(alias)
        log_msg('[get_disk_alias] {}'.format(alias))
        return alias
    except Exception as e:
        msg = "Exception={0}".format(e)
        log_msg("[get_disk_alias] " + msg)
        return []


if __name__ == "__main__":
    alias_dev = get_disk_alias()
    json_data = json.dumps(alias_dev)
    log_msg("\n")
    log_msg(json_data)
    log_msg("\n")
