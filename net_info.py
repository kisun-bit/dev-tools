import psutil


def adapter_info() -> list:
    """
    本机所有网卡信息

    :return:
    [
        {
            'adapter_name': '以太网 2',
            'adapter_address': [
                {
                    'type': 4, // 4 or 6
                    'ipv4': '192.168.10.64',
                    'ipv6': "",
                    'mask': '255.255.255.0',
                    'mac': '18-C0-4D-43-AE-B8'
                },
                ...
            ]
        },
        ...
    ]
    """
    adapters = list()

    as_ = psutil.net_if_addrs()
    for adapter in as_:
        one_adapter = dict()
        one_adapter['adapter_name'] = adapter
        one_adapter['adapter_addresses'] = list()

        for address in as_[adapter]:  # type: psutil._common.snicaddr
            one_address = dict(
                type=None, ipv4=None, ipv6=None, mask=None, mac=None, broadcast=None)

            family = address.family  # type: psutil._pswindows.AddressFamily or psutil._pslinux.AddressFamily
            if family.name in ('AF_LINK', 'AF_PACKET'):
                one_address['mac'] = address.address
            elif family.name == 'AF_INET':
                one_address['ipv4'] = address.address
            elif family.name == 'AF_INET6':
                one_address['ipv6'] = address.address

            one_address['mask'] = address.netmask
            one_address['broadcast'] = address.broadcast
            one_adapter['adapter_addresses'].append(one_address)

        adapters.append(one_adapter)
    return adapters


if __name__ == '__main__':
    from pprint import pprint

    pprint(adapter_info())
