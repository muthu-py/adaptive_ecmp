def get_host_bandwidth(net, host_name):
    host = net.get(host_name)
    stats = host.cmd("cat /proc/net/dev | grep eth0")
    bytes_rx = int(stats.split()[1])
    bytes_tx = int(stats.split()[9])
    return bytes_rx, bytes_tx