from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
import threading
import os
import ipaddress
import mysql.connector

IFACE = "Realtek 8822CE Wireless LAN 802.11ac PCI-E NIC"
RULE_FILE_NAME = "Rule.txt"
STOP_FILTER = False

# 创建数据库连接
config = {
    'user': 'root',
    'password': 'GJSE8YqDww',
    'host': 'localhost',
    'database': 'firewall',
    'raise_on_warnings': True
}
cnx = mysql.connector.connect(**config)
cursor = cnx.cursor(dictionary=True)

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def read_filter_rules(filter_file):
    """
    读取过滤规则
    """
    rules = []
    with open(filter_file, "r") as f:
        for line in f.readlines():
            rule = line.strip().split(" ")
            if len(rule) == 3 and (rule[0] == "permit" or rule[0] == "deny") and rule[1] == "source":
                action = rule[0]
                src_address = rule[2]
                dst_address = "any"
                rules.append((action, src_address, dst_address))
    return rules


def write_filter_rules(filter_file, rules):
    with open(filter_file, "w") as f:
        for rule in rules:
            f.write(f"{rule[0]} source {rule[1]}\n")


def add_rule(rules):
    global stop_filter
    # 停止防火墙线程
    stop_filter = True

    while True:
        action = input("输入 permit 或 deny：")
        if action == 'permit':
            break
        elif action == 'deny':
            break
        else:
            print("输入的操作不是有效的操作，请重新输入。")
    while True:
        src_address = input("输入源地址：")
        if validate_ip(src_address):
            break
        print("输入的源地址不是有效的IP地址，请重新输入。")
    dst_address = "any"
    rules.append((action, src_address, dst_address))
    with open(RULE_FILE_NAME, "a") as f:  # 使用 "a" 模式来追加内容
        f.write(f"{action} source {src_address}\n")
    print(f"已添加规则：{action} source {src_address} -> {dst_address}")
    # 重新读取规则
    rules = read_filter_rules(RULE_FILE_NAME)
    # 重启防火墙线程
    stop_filter = False
    firewall_thread = threading.Thread(target=start_firewall, args=(rules,))
    firewall_thread.start()



def display_rules():
    """
    显示当前所有规则以及其索引
    """
    rules = read_filter_rules(RULE_FILE_NAME)
    for i, rule in enumerate(rules):
        print(f"{i}: {rule[0]} source {rule[1]} -> {rule[2]}")


def get_valid_index(rules):
    """
    获取一个有效的规则索引
    """
    while True:
        idx = input("输入要删除规则的索引：")
        if idx.isdigit():
            idx = int(idx)
            if 0 <= idx < len(rules):
                return idx
            else:
                print("输入的索引超出了范围，请重新输入。")
        else:
            print("输入的不是有效的数字，请重新输入。")


def del_rule(rules):
    """
    删除规则
    """
    global stop_filter
    # 停止防火墙线程
    stop_filter = True

    idx = get_valid_index(rules)
    new_rules = []
    for i, rule in enumerate(rules):
        if i != idx:
            new_rules.append(rule)
        else:
            print(f"已删除规则：{rule[0]} source {rule[1]} -> {rule[2]}")
    write_filter_rules(RULE_FILE_NAME, new_rules)
    # 重新读取规则
    rules = read_filter_rules(RULE_FILE_NAME)
    # 重启防火墙线程
    stop_filter = False
    firewall_thread = threading.Thread(target=start_firewall, args=(rules,))
    firewall_thread.start()


def manage_rules(rules):
    while True:
        print("输入操作：add 添加规则，del 删除规则，show 显示规则，exit 退出程序")
        action = input("输入操作：")
        if action == "add":
            add_rule(rules)
        elif action == "del":
            del_rule(rules)
        elif action == "show":
            display_rules()
        elif action == "exit":
            os._exit(0)  # 使用 os._exit 退出整个程序，包括所有线程
        else:
            print("无效的操作，请重试。")


def forward_packet(pkt):  # 转发数据包
    # 修改数据包中的MAC地址和IP地址（将源地址改为目标地址，目标地址改为源地址）
    pkt[Ether].src, pkt[Ether].dst = pkt[Ether].dst, pkt[Ether].src
    pkt[IP].src, pkt[IP].dst = pkt[IP].dst, pkt[IP].src
    # 发送数据包到网络接口
    sendp(pkt, iface=pkt.sniffed_on)


def drop_packet(pkt):  # 直接丢弃数据包
    # 丢弃数据包
    pass


def process_packet(p, rules):  # 处理数据包
    if p.haslayer(IP):  # 检查是否存在 IP 层
        # 根据源 IP 地址匹配过滤规则
        matched = any(
            (rule[0] == "permit") and
            ((rule[1] == "any") or (p[IP].src == rule[1]))
            for rule in rules
        )

        if matched:
            forward_packet(p)
        else:
            drop_packet(p)


def start_firewall(rules):  # 启动防火墙程序
    # 使用sniff函数捕获数据包，并将其传递给回调函数进行处理
    sniff(prn=lambda x: process_packet(x, rules), store=0, iface=IFACE, stop_filter=lambda _: STOP_FILTER)


if __name__ == "__main__":
    rules = read_filter_rules(RULE_FILE_NAME)

    firewall_thread = threading.Thread(target=start_firewall, args=(rules,))
    firewall_thread.start()

    manage_rules_thread = threading.Thread(target=manage_rules, args=(rules,))
    manage_rules_thread.start()
