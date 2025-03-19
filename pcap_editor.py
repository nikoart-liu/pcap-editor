#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PCAP Editor - 一个用于读取、修改和保存pcap文件的工具

使用方法:
    python pcap_editor.py -r input.pcap -w output.pcap [options]

选项:
    -r, --read      输入pcap文件路径
    -w, --write     输出pcap文件路径
    --src-ip        修改源IP地址 (例如: --src-ip 192.168.1.1:10.0.0.1)
    --dst-ip        修改目标IP地址 (例如: --dst-ip 192.168.1.2:10.0.0.2)
    --src-port      修改源端口 (例如: --src-port 80:8080)
    --dst-port      修改目标端口 (例如: --dst-port 80:8080)
    --ttl           修改TTL值 (例如: --ttl 64:128)
    --tos           修改TOS值 (例如: --tos 0:16)
    -h, --help      显示帮助信息
"""

import argparse
import sys
from scapy.all import *
import re


def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='PCAP文件编辑工具')
    parser.add_argument('-r', '--read', required=True, help='输入pcap文件路径')
    parser.add_argument('-w', '--write', required=True, help='输出pcap文件路径')
    parser.add_argument('--src-ip', help='修改源IP地址 (例如: 192.168.1.1:10.0.0.1)')
    parser.add_argument('--dst-ip', help='修改目标IP地址 (例如: 192.168.1.2:10.0.0.2)')
    parser.add_argument('--src-port', help='修改源端口 (例如: 80:8080)')
    parser.add_argument('--dst-port', help='修改目标端口 (例如: 80:8080)')
    parser.add_argument('--ttl', help='修改TTL值 (例如: 64:128)')
    parser.add_argument('--tos', help='修改TOS值 (例如: 0:16)')
    parser.add_argument('--offset', type=int, help='修改RAW部分，偏移量（整数）')
    parser.add_argument('--length', type=int, help='修改RAW部分，长度（整数）')
    parser.add_argument('--data', help='修改RAW部分，新值（十六进制字符串，如"AABBCC"）')
    
    return parser.parse_args()


def parse_replacement(replacement_str):
    """解析替换字符串，格式为 'old:new' 或 ':new'（直接替换）"""
    if not replacement_str or ':' not in replacement_str:
        return None, None
    
    parts = replacement_str.split(':', 1)
    if len(parts) == 2:
        old_val, new_val = parts
        old_val = old_val.strip()
        new_val = new_val.strip()
        return old_val if old_val else None, new_val
    return None, None


def modify_packet(packet, args):
    """根据参数修改数据包"""
    modified = False
    
    # 处理IP层
    if IP in packet:
        # 修改源IP
        if args.src_ip:
            old_ip, new_ip = parse_replacement(args.src_ip)
            if old_ip and new_ip and packet[IP].src == old_ip:
                packet[IP].src = new_ip
                modified = True
        
        # 修改目标IP
        if args.dst_ip:
            old_ip, new_ip = parse_replacement(args.dst_ip)
            if old_ip and new_ip and packet[IP].dst == old_ip:
                packet[IP].dst = new_ip
                modified = True
        
        # 修改TTL
        if args.ttl:
            old_ttl, new_ttl = parse_replacement(args.ttl)
            if old_ttl and new_ttl and packet[IP].ttl == int(old_ttl):
                packet[IP].ttl = int(new_ttl)
                modified = True
        
        # 修改TOS
        if args.tos:
            old_tos, new_tos = parse_replacement(args.tos)
            if old_tos and new_tos and packet[IP].tos == int(old_tos):
                packet[IP].tos = int(new_tos)
                modified = True
    
    # 处理TCP/UDP层
    if TCP in packet:
        # 修改源端口
        if args.src_port:
            old_port, new_port = parse_replacement(args.src_port)
            if old_port and new_port and packet[TCP].sport == int(old_port):
                packet[TCP].sport = int(new_port)
                modified = True
        
        # 修改目标端口
        if args.dst_port:
            old_port, new_port = parse_replacement(args.dst_port)
            if old_port and new_port and packet[TCP].dport == int(old_port):
                packet[TCP].dport = int(new_port)
                modified = True
                
        # 修改TCP payload
        if Raw in packet and args.offset is not None and args.length is not None and args.data is not None:
            original_load = packet[Raw].load
            print(f"Original Data: {original_load.hex()}")
            
            # 将数据转换为可修改的bytearray
            modified_load = bytearray(original_load)
            offset = args.offset
            length = args.length
            
            # 将十六进制字符串转换为字节
            try:
                data = bytes.fromhex(args.data)
            except ValueError:
                print(f"错误: 数据'{args.data}'不是有效的十六进制字符串")
                return False
            
            # 验证偏移和长度有效性
            if offset < 0 or offset >= len(modified_load):
                print(f"错误: 偏移量{offset}超出数据范围(0-{len(modified_load)-1})")
                return False
                
            if offset + length > len(modified_load):
                print(f"错误: 偏移量({offset}) + 长度({length}) = {offset+length} 超出数据大小({len(modified_load)})!")
                return False
            
            # 替换指定位置的字节
            modified_load[offset:offset+length] = data
            
            # 更新报文数据
            packet[Raw].load = bytes(modified_load)
            print(f"Modified Data: {packet[Raw].load.hex()}")
            modified = True
        elif Raw in packet and (args.offset is not None or args.length is not None or args.data is not None):
            print("错误: 修改TCP payload需要同时指定--offset、--length和--data参数")
            return False
    
    elif UDP in packet:
        # 修改源端口
        if args.src_port:
            old_port, new_port = parse_replacement(args.src_port)
            if old_port and new_port and packet[UDP].sport == int(old_port):
                packet[UDP].sport = int(new_port)
                modified = True
        
        # 修改目标端口
        if args.dst_port:
            old_port, new_port = parse_replacement(args.dst_port)
            if old_port and new_port and packet[UDP].dport == int(old_port):
                packet[UDP].dport = int(new_port)
                modified = True
                
        # 修改UDP payload
        if Raw in packet and args.offset is not None and args.length is not None and args.data is not None:
            original_load = packet[Raw].load
            print(f"Original Data: {original_load.hex()}")
            
            # 将数据转换为可修改的bytearray
            modified_load = bytearray(original_load)
            offset = args.offset
            length = args.length
            
            # 将十六进制字符串转换为字节
            try:
                data = bytes.fromhex(args.data)
            except ValueError:
                print(f"错误: 数据'{args.data}'不是有效的十六进制字符串")
                return False
            
            # 验证偏移和长度有效性
            if offset < 0 or offset >= len(modified_load):
                print(f"错误: 偏移量{offset}超出数据范围(0-{len(modified_load)-1})")
                return False
                
            if offset + length > len(modified_load):
                print(f"错误: 偏移量({offset}) + 长度({length}) = {offset+length} 超出数据大小({len(modified_load)})!")
                return False
            
            # 替换指定位置的字节
            modified_load[offset:offset+length] = data
            
            # 更新报文数据
            packet[Raw].load = bytes(modified_load)
            print(f"Modified Data: {packet[Raw].load.hex()}")
            modified = True
        elif Raw in packet and (args.offset is not None or args.length is not None or args.data is not None):
            print("错误: 修改UDP payload需要同时指定--offset、--length和--data参数")
            return False    
    # 如果修改了数据包，需要删除校验和，让scapy重新计算
    if modified and IP in packet:
        del packet[IP].chksum
        if TCP in packet:
            del packet[TCP].chksum
        elif UDP in packet:
            del packet[UDP].chksum
    
    return modified


def main():
    args = parse_arguments()
    
    try:
        # 读取pcap文件
        print(f"正在读取pcap文件: {args.read}")
        packets = rdpcap(args.read)
        
        # 统计信息
        total_packets = len(packets)
        modified_packets = 0
        
        # 修改数据包
        for i, packet in enumerate(packets):
            if modify_packet(packet, args):
                modified_packets += 1
                if modified_packets % 100 == 0:
                    print(f"已修改 {modified_packets} 个数据包...")
        
        # 保存修改后的数据包
        print(f"正在保存修改后的pcap文件: {args.write}")
        wrpcap(args.write, packets)
        
        print(f"处理完成! 总共处理 {total_packets} 个数据包，修改了 {modified_packets} 个数据包。")
        
    except FileNotFoundError:
        print(f"错误: 找不到文件 {args.read}")
        return 1
    except Exception as e:
        print(f"错误: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())