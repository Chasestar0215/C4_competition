"""
Function:
    manage_rules

Parameters:
    

Returns:
    

Author:
    Jerry

Date:
    2023/06/19 09:43

Description:
    Description of the method/function.
"""
# manage_rules.py
import os

RULE_FILE_NAME="Rule.txt"

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
    action = input("输入 permit 或 deny：")
    src_address = input("输入源地址：")
    dst_address = "any"
    rules.append((action, src_address, dst_address))
    with open(RULE_FILE_NAME, "a") as f:  # 使用 "a" 模式来追加内容
        f.write(f"{action} source {src_address}\n")
    print(f"已添加规则：{action} source {src_address} -> {dst_address}")

def del_rule(rules):
    idx = int(input("输入要删除规则的索引："))
    new_rules = []
    for i, rule in enumerate(rules):
        if i != idx:
            new_rules.append(rule)
        else:
            print(f"已删除规则：{rule[0]} source {rule[1]} -> {rule[2]}")
    write_filter_rules(RULE_FILE_NAME, new_rules)

def manage_rules():
    rules = read_filter_rules(RULE_FILE_NAME)
    while True:
        print("输入操作：add 添加规则，del 删除规则，exit 退出程序")
        action = input("输入操作：")
        if action == "add":
            add_rule(rules)
        elif action == "del":
            del_rule(rules)
        elif action == "exit":
            break
        else:
            print("无效的操作，请重试。")

if __name__ == "__main__":
    manage_rules()
