#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PCAP Editor GUI - PCAP编辑器的图形用户界面
基于原有的pcap_editor.py命令行工具功能
"""

import sys
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QPushButton, QLabel, QLineEdit, QFileDialog, QGroupBox, 
                            QFormLayout, QTableWidget, QTableWidgetItem, QHeaderView, 
                            QMessageBox, QTabWidget, QTextEdit, QSpinBox, QCheckBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon, QFont

# 导入原有的pcap_editor模块功能
from pcap_editor import modify_packet, parse_replacement
from scapy.all import rdpcap, wrpcap, IP, TCP, UDP, Raw, ICMP, Ether


class PacketProcessingThread(QThread):
    """用于后台处理数据包的线程"""
    progress_update = pyqtSignal(int, int)  # 当前处理数量, 总数
    finished_signal = pyqtSignal(int)  # 修改的数据包数量
    error_signal = pyqtSignal(str)  # 错误信息

    def __init__(self, input_file, output_file, params):
        super().__init__()
        self.input_file = input_file
        self.output_file = output_file
        self.params = params

    def run(self):
        try:
            # 读取pcap文件
            packets = rdpcap(self.input_file)
            
            # 统计信息
            total_packets = len(packets)
            modified_packets = 0
            
            # 创建一个类似于args的对象
            class Args:
                pass
            
            args = Args()
            for key, value in self.params.items():
                setattr(args, key, value)
            
            # 修改数据包
            for i, packet in enumerate(packets):
                if modify_packet(packet, args):
                    modified_packets += 1
                
                # 每处理10个数据包更新一次进度
                if (i + 1) % 10 == 0 or i == total_packets - 1:
                    self.progress_update.emit(i + 1, total_packets)
            
            # 保存修改后的数据包
            wrpcap(self.output_file, packets)
            
            # 发送完成信号
            self.finished_signal.emit(modified_packets)
            
        except Exception as e:
            self.error_signal.emit(str(e))


class PCAPEditorGUI(QMainWindow):
    """PCAP编辑器的主窗口"""
    
    def __init__(self):
        super().__init__()
        self.packets = None  # 存储加载的数据包
        self.initUI()
        
    def initUI(self):
        # 设置窗口标题和大小
        self.setWindowTitle('PCAP编辑器')
        self.setGeometry(100, 100, 800, 600)
        
        # 设置应用程序图标
        icon_path = os.path.join(os.path.dirname(__file__), 'resources', 'pcap_editor.png')
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        
        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QVBoxLayout(central_widget)
        
        # 文件选择区域
        file_group = QGroupBox("文件选择")
        file_layout = QFormLayout()
        
        # 输入文件
        self.input_file_edit = QLineEdit()
        self.input_file_btn = QPushButton("浏览...")
        self.input_file_btn.clicked.connect(self.browse_input_file)
        input_file_layout = QHBoxLayout()
        input_file_layout.addWidget(self.input_file_edit)
        input_file_layout.addWidget(self.input_file_btn)
        file_layout.addRow("输入PCAP文件:", input_file_layout)
        
        # 输出文件
        self.output_file_edit = QLineEdit()
        self.output_file_btn = QPushButton("浏览...")
        self.output_file_btn.clicked.connect(self.browse_output_file)
        output_file_layout = QHBoxLayout()
        output_file_layout.addWidget(self.output_file_edit)
        output_file_layout.addWidget(self.output_file_btn)
        file_layout.addRow("输出PCAP文件:", output_file_layout)
        
        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)
        
        # 创建选项卡
        tabs = QTabWidget()
        
        # IP修改选项卡之前添加MAC修改选项卡
        mac_tab = QWidget()
        mac_layout = QFormLayout(mac_tab)
        
        self.src_mac_edit = QLineEdit()
        self.src_mac_edit.setPlaceholderText("格式: 00:11:22:33:44:55>aa:bb:cc:dd:ee:ff")
        self.src_mac_edit.setMinimumWidth(300)
        mac_layout.addRow("修改源MAC:", self.src_mac_edit)
        
        self.dst_mac_edit = QLineEdit()
        self.dst_mac_edit.setPlaceholderText("格式: 00:11:22:33:44:55>aa:bb:cc:dd:ee:ff")
        self.dst_mac_edit.setMinimumWidth(300)
        mac_layout.addRow("修改目标MAC:", self.dst_mac_edit)
        
        tabs.addTab(mac_tab, "MAC选项")
        
        # IP修改选项卡
        ip_tab = QWidget()
        ip_layout = QFormLayout(ip_tab)
        
        self.src_ip_edit = QLineEdit()
        self.src_ip_edit.setPlaceholderText("格式: 192.168.1.1:10.0.0.1")
        self.src_ip_edit.setMinimumWidth(300)
        ip_layout.addRow("修改源IP:", self.src_ip_edit)
        
        self.dst_ip_edit = QLineEdit()
        self.dst_ip_edit.setPlaceholderText("格式: 192.168.1.2:10.0.0.2")
        self.dst_ip_edit.setMinimumWidth(300)
        ip_layout.addRow("修改目标IP:", self.dst_ip_edit)
        
        self.ttl_edit = QLineEdit()
        self.ttl_edit.setPlaceholderText("格式: 64:128")
        ip_layout.addRow("修改TTL值:", self.ttl_edit)
        
        self.tos_edit = QLineEdit()
        self.tos_edit.setPlaceholderText("格式: 0:16")
        ip_layout.addRow("修改TOS值:", self.tos_edit)
        
        tabs.addTab(ip_tab, "IP选项")
        
        # TCP/UDP修改选项卡
        port_tab = QWidget()
        port_layout = QFormLayout(port_tab)
        
        self.src_port_edit = QLineEdit()
        self.src_port_edit.setPlaceholderText("格式: 80:8080")
        port_layout.addRow("修改源端口:", self.src_port_edit)
        
        self.dst_port_edit = QLineEdit()
        self.dst_port_edit.setPlaceholderText("格式: 80:8080")
        port_layout.addRow("修改目标端口:", self.dst_port_edit)
        
        tabs.addTab(port_tab, "端口选项")
        
        # Payload修改选项卡
        payload_tab = QWidget()
        payload_layout = QFormLayout(payload_tab)
        
        self.offset_spin = QSpinBox()
        self.offset_spin.setRange(0, 9999)
        payload_layout.addRow("偏移量:", self.offset_spin)
        
        self.length_spin = QSpinBox()
        self.length_spin.setRange(1, 9999)
        payload_layout.addRow("长度:", self.length_spin)
        
        self.data_edit = QTextEdit()
        self.data_edit.setPlaceholderText("十六进制数据，如: AABBCC")
        payload_layout.addRow("新数据(十六进制):", self.data_edit)
        
        self.enable_payload_edit = QCheckBox("启用Payload修改")
        payload_layout.addRow(self.enable_payload_edit)
        
        tabs.addTab(payload_tab, "Payload修改")
        
        # 添加数据包预览选项卡
        preview_tab = QWidget()
        preview_layout = QVBoxLayout(preview_tab)
        
        # 添加加载预览按钮
        load_preview_btn = QPushButton("加载数据包预览")
        load_preview_btn.clicked.connect(self.load_packet_preview)
        preview_layout.addWidget(load_preview_btn)
        
        # 添加数据包表格
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels(["序号", "时间", "源IP", "目标IP", "协议", "长度", "信息"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        preview_layout.addWidget(self.packet_table)
        
        # 添加数据包详情区域
        packet_details_group = QGroupBox("数据包详情")
        packet_details_layout = QVBoxLayout()
        self.packet_details_text = QTextEdit()
        self.packet_details_text.setReadOnly(True)
        packet_details_layout.addWidget(self.packet_details_text)
        packet_details_group.setLayout(packet_details_layout)
        preview_layout.addWidget(packet_details_group)
        
        # 连接表格选择事件
        self.packet_table.itemSelectionChanged.connect(self.show_packet_details)
        
        tabs.addTab(preview_tab, "数据包预览")
        
        # 添加统计信息选项卡
        stats_tab = QWidget()
        stats_layout = QVBoxLayout(stats_tab)
        
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        stats_layout.addWidget(self.stats_text)
        
        # 添加生成统计按钮
        generate_stats_btn = QPushButton("生成统计信息")
        generate_stats_btn.clicked.connect(self.generate_statistics)
        stats_layout.addWidget(generate_stats_btn)
        
        tabs.addTab(stats_tab, "统计信息")
        
        # 日志选项卡
        log_tab = QWidget()
        log_layout = QVBoxLayout(log_tab)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        log_layout.addWidget(self.log_text)
        
        tabs.addTab(log_tab, "日志")
        
        main_layout.addWidget(tabs)
        
        # 进度显示
        progress_layout = QHBoxLayout()
        self.progress_label = QLabel("就绪")
        progress_layout.addWidget(self.progress_label)
        main_layout.addLayout(progress_layout)
        
        # 操作按钮
        button_layout = QHBoxLayout()
        
        self.process_btn = QPushButton("处理PCAP文件")
        self.process_btn.clicked.connect(self.process_pcap)
        self.process_btn.setMinimumHeight(40)
        button_layout.addWidget(self.process_btn)
        
        main_layout.addLayout(button_layout)
        
        # 初始化处理线程
        self.processing_thread = None
        
        # 显示窗口
        self.show()
        
    def browse_input_file(self):
        """浏览并选择输入文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择PCAP文件", "", "PCAP文件 (*.pcap *.pcapng);;所有文件 (*.*)"
        )
        if file_path:
            self.input_file_edit.setText(file_path)
            # 如果输出文件为空，自动生成输出文件名
            if not self.output_file_edit.text():
                dir_name, file_name = os.path.split(file_path)
                base_name, ext = os.path.splitext(file_name)
                output_path = os.path.join(dir_name, f"{base_name}_modified{ext}")
                self.output_file_edit.setText(output_path)
    
    def browse_output_file(self):
        """浏览并选择输出文件"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存PCAP文件", "", "PCAP文件 (*.pcap *.pcapng);;所有文件 (*.*)"
        )
        if file_path:
            self.output_file_edit.setText(file_path)
    
    def log(self, message):
        """添加日志消息"""
        self.log_text.append(message)
    
    def process_pcap(self):
        """处理PCAP文件"""
        # 检查输入和输出文件
        input_file = self.input_file_edit.text()
        output_file = self.output_file_edit.text()
        
        if not input_file:
            QMessageBox.warning(self, "错误", "请选择输入PCAP文件")
            return
        
        if not output_file:
            QMessageBox.warning(self, "错误", "请选择输出PCAP文件")
            return
        
        if not os.path.exists(input_file):
            QMessageBox.warning(self, "错误", f"输入文件不存在: {input_file}")
            return
        
        # 收集参数
        params = {
            'src_mac': self.src_mac_edit.text() if self.src_mac_edit.text() else None,
            'dst_mac': self.dst_mac_edit.text() if self.dst_mac_edit.text() else None,
            'src_ip': self.src_ip_edit.text() if self.src_ip_edit.text() else None,
            'dst_ip': self.dst_ip_edit.text() if self.dst_ip_edit.text() else None,
            'src_port': self.src_port_edit.text() if self.src_port_edit.text() else None,
            'dst_port': self.dst_port_edit.text() if self.dst_port_edit.text() else None,
            'ttl': self.ttl_edit.text() if self.ttl_edit.text() else None,
            'tos': self.tos_edit.text() if self.tos_edit.text() else None,
        }
        
        # 如果启用了Payload修改，添加相关参数
        if self.enable_payload_edit.isChecked():
            params['offset'] = self.offset_spin.value()
            params['length'] = self.length_spin.value()
            params['data'] = self.data_edit.text()
        else:
            params['offset'] = None
            params['length'] = None
            params['data'] = None
        
        # 禁用处理按钮
        self.process_btn.setEnabled(False)
        self.progress_label.setText("正在处理...")
        
        # 清空日志
        self.log_text.clear()
        
        # 记录开始处理的日志
        self.log(f"开始处理PCAP文件: {input_file}")
        self.log(f"输出文件: {output_file}")
        for key, value in params.items():
            if value:
                self.log(f"参数 {key}: {value}")
        
        # 创建并启动处理线程
        self.processing_thread = PacketProcessingThread(input_file, output_file, params)
        self.processing_thread.progress_update.connect(self.update_progress)
        self.processing_thread.finished_signal.connect(self.processing_finished)
        self.processing_thread.error_signal.connect(self.processing_error)
        self.processing_thread.start()
    
    def update_progress(self, current, total):
        """更新进度显示"""
        self.progress_label.setText(f"处理进度: {current}/{total} ({current/total*100:.1f}%)")
    
    def processing_finished(self, modified_count):
        """处理完成的回调"""
        self.process_btn.setEnabled(True)
        self.progress_label.setText(f"处理完成! 修改了 {modified_count} 个数据包")
        self.log(f"处理完成! 修改了 {modified_count} 个数据包")
        
        QMessageBox.information(self, "处理完成", f"成功处理PCAP文件!\n修改了 {modified_count} 个数据包")
    
    def processing_error(self, error_message):
        """处理错误的回调"""
        self.process_btn.setEnabled(True)
        self.progress_label.setText(f"处理出错: {error_message}")
        self.log(f"错误: {error_message}")
        
        QMessageBox.critical(self, "处理错误", f"处理PCAP文件时出错:\n{error_message}")
    
    def load_packet_preview(self):
        """加载数据包预览"""
        input_file = self.input_file_edit.text()
        
        if not input_file:
            QMessageBox.warning(self, "错误", "请先选择输入PCAP文件")
            return
        
        if not os.path.exists(input_file):
            QMessageBox.warning(self, "错误", f"输入文件不存在: {input_file}")
            return
        
        try:
            # 显示加载中消息
            self.log("正在加载数据包预览...")
            self.progress_label.setText("正在加载数据包...")
            
            # 清空表格
            self.packet_table.setRowCount(0)
            
            # 读取pcap文件
            self.packets = rdpcap(input_file)
            
            # 设置表格行数
            self.packet_table.setRowCount(len(self.packets))
            
            # 填充表格
            for i, packet in enumerate(self.packets):
                # 序号
                self.packet_table.setItem(i, 0, QTableWidgetItem(str(i+1)))
                
                # 时间 (如果有)
                time_str = packet.time if hasattr(packet, 'time') else "-"
                self.packet_table.setItem(i, 1, QTableWidgetItem(str(time_str)))
                
                # MAC地址
                if Ether in packet:
                    self.packet_table.setItem(i, 2, QTableWidgetItem(packet[Ether].src))
                    self.packet_table.setItem(i, 3, QTableWidgetItem(packet[Ether].dst))
                else:
                    self.packet_table.setItem(i, 2, QTableWidgetItem("-"))
                    self.packet_table.setItem(i, 3, QTableWidgetItem("-"))
                
                # IP地址
                if IP in packet:
                    self.packet_table.setItem(i, 4, QTableWidgetItem(packet[IP].src))
                    self.packet_table.setItem(i, 5, QTableWidgetItem(packet[IP].dst))
                else:
                    self.packet_table.setItem(i, 4, QTableWidgetItem("-"))
                    self.packet_table.setItem(i, 5, QTableWidgetItem("-"))
                
                # 协议
                proto = "-"
                if TCP in packet:
                    proto = "TCP"
                elif UDP in packet:
                    proto = "UDP"
                elif ICMP in packet:
                    proto = "ICMP"
                self.packet_table.setItem(i, 6, QTableWidgetItem(proto))
                
                # 长度
                self.packet_table.setItem(i, 7, QTableWidgetItem(str(len(packet))))
                
                # 信息
                info = "-"
                if TCP in packet:
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    flags = packet[TCP].flags
                    info = f"TCP {sport} → {dport} [Flags: {flags}]"
                elif UDP in packet:
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    info = f"UDP {sport} → {dport}"
                elif ICMP in packet:
                    info = "ICMP"
                self.packet_table.setItem(i, 8, QTableWidgetItem(info))

            # 调整列宽
            self.packet_table.resizeColumnsToContents()
            
            self.log(f"已加载 {len(self.packets)} 个数据包")
            self.progress_label.setText(f"已加载 {len(self.packets)} 个数据包")
            
        except Exception as e:
            self.log(f"加载数据包预览时出错: {str(e)}")
            self.progress_label.setText("加载数据包预览失败")
            QMessageBox.critical(self, "错误", f"加载数据包预览时出错:\n{str(e)}")
    
    def show_packet_details(self):
        """显示选中数据包的详情"""
        if not self.packets:
            return
        
        selected_items = self.packet_table.selectedItems()
        if not selected_items:
            return
        
        # 获取选中的行
        row = selected_items[0].row()
        
        # 获取对应的数据包
        packet = self.packets[row]
        
        # 显示详情
        self.packet_details_text.clear()
        self.packet_details_text.append(f"<h3>数据包 #{row+1} 详情</h3>")
        
        # 显示原始数据包信息
        self.packet_details_text.append("<pre>")
        packet_info = packet.show(dump=True)
        self.packet_details_text.append(packet_info)
        self.packet_details_text.append("</pre>")
        
        # 如果有Raw数据，显示十六进制和ASCII
        if Raw in packet:
            raw_data = packet[Raw].load
            self.packet_details_text.append("<h4>Raw数据 (十六进制)</h4>")
            self.packet_details_text.append("<pre>")
            
            # 格式化十六进制显示
            hex_dump = ""
            ascii_dump = ""
            for i, byte in enumerate(raw_data):
                if i % 16 == 0 and i > 0:
                    hex_dump += f"  {ascii_dump}\n"
                    ascii_dump = ""
                
                hex_dump += f"{byte:02x} "
                
                # ASCII部分 (只显示可打印字符)
                if 32 <= byte <= 126:
                    ascii_dump += chr(byte)
                else:
                    ascii_dump += "."
            
            # 处理最后一行
            if ascii_dump:
                # 计算需要补充的空格
                padding = " " * (3 * (16 - len(ascii_dump)))
                hex_dump += f"{padding}  {ascii_dump}"
            
            self.packet_details_text.append(hex_dump)
            self.packet_details_text.append("</pre>")
    
    def generate_statistics(self):
        """生成统计信息"""
        input_file = self.input_file_edit.text()
        
        if not input_file:
            QMessageBox.warning(self, "错误", "请先选择输入PCAP文件")
            return
        
        if not os.path.exists(input_file):
            QMessageBox.warning(self, "错误", f"输入文件不存在: {input_file}")
            return
        
        try:
            # 如果还没有加载数据包，先加载
            if not self.packets:
                self.packets = rdpcap(input_file)
            
            # 清空统计信息
            self.stats_text.clear()
            
            # 基本信息
            total_packets = len(self.packets)
            self.stats_text.append(f"<h3>PCAP文件统计信息</h3>")
            self.stats_text.append(f"<p>文件: {input_file}</p>")
            self.stats_text.append(f"<p>总数据包数: {total_packets}</p>")
            
            if total_packets == 0:
                self.stats_text.append("<p>没有数据包可供分析</p>")
                return
            
            # 协议分布
            self.stats_text.append("<h4>协议分布</h4>")
            
            tcp_count = sum(1 for p in self.packets if TCP in p)
            udp_count = sum(1 for p in self.packets if UDP in p)
            icmp_count = sum(1 for p in self.packets if ICMP in p)
            other_count = total_packets - tcp_count - udp_count - icmp_count
            
            self.stats_text.append(f"<p>TCP: {tcp_count} ({tcp_count/total_packets*100:.1f}%)</p>")
            self.stats_text.append(f"<p>UDP: {udp_count} ({udp_count/total_packets*100:.1f}%)</p>")
            self.stats_text.append(f"<p>ICMP: {icmp_count} ({icmp_count/total_packets*100:.1f}%)</p>")
            self.stats_text.append(f"<p>其他: {other_count} ({other_count/total_packets*100:.1f}%)</p>")
            
            # IP地址统计
            if any(IP in p for p in self.packets):
                self.stats_text.append("<h4>IP地址统计</h4>")
                
                # 源IP统计
                src_ips = {}
                for p in self.packets:
                    if IP in p:
                        src_ip = p[IP].src
                        src_ips[src_ip] = src_ips.get(src_ip, 0) + 1
                
                self.stats_text.append("<p><b>前10个源IP地址:</b></p>")
                self.stats_text.append("<ul>")
                for ip, count in sorted(src_ips.items(), key=lambda x: x[1], reverse=True)[:10]:
                    self.stats_text.append(f"<li>{ip}: {count} 个数据包 ({count/total_packets*100:.1f}%)</li>")
                self.stats_text.append("</ul>")
                
                # 目标IP统计
                dst_ips = {}
                for p in self.packets:
                    if IP in p:
                        dst_ip = p[IP].dst
                        dst_ips[dst_ip] = dst_ips.get(dst_ip, 0) + 1
                
                self.stats_text.append("<p><b>前10个目标IP地址:</b></p>")
                self.stats_text.append("<ul>")
                for ip, count in sorted(dst_ips.items(), key=lambda x: x[1], reverse=True)[:10]:
                    self.stats_text.append(f"<li>{ip}: {count} 个数据包 ({count/total_packets*100:.1f}%)</li>")
                self.stats_text.append("</ul>")
            
            # 端口统计
            if tcp_count > 0 or udp_count > 0:
                self.stats_text.append("<h4>端口统计</h4>")
                
                # TCP源端口
                if tcp_count > 0:
                    tcp_src_ports = {}
                    for p in self.packets:
                        if TCP in p:
                            port = p[TCP].sport
                            tcp_src_ports[port] = tcp_src_ports.get(port, 0) + 1
                    
                    self.stats_text.append("<p><b>前10个TCP源端口:</b></p>")
                    self.stats_text.append("<ul>")
                    for port, count in sorted(tcp_src_ports.items(), key=lambda x: x[1], reverse=True)[:10]:
                        self.stats_text.append(f"<li>{port}: {count} 个数据包 ({count/tcp_count*100:.1f}%)</li>")
                    self.stats_text.append("</ul>")
                    
                    # TCP目标端口
                    tcp_dst_ports = {}
                    for p in self.packets:
                        if TCP in p:
                            port = p[TCP].dport
                            tcp_dst_ports[port] = tcp_dst_ports.get(port, 0) + 1
                    
                    self.stats_text.append("<p><b>前10个TCP目标端口:</b></p>")
                    self.stats_text.append("<ul>")
                    for port, count in sorted(tcp_dst_ports.items(), key=lambda x: x[1], reverse=True)[:10]:
                        self.stats_text.append(f"<li>{port}: {count} 个数据包 ({count/tcp_count*100:.1f}%)</li>")
                    self.stats_text.append("</ul>")
                
                # UDP端口统计
                if udp_count > 0:
                    udp_src_ports = {}
                    for p in self.packets:
                        if UDP in p:
                            port = p[UDP].sport
                            udp_src_ports[port] = udp_src_ports.get(port, 0) + 1
                    
                    self.stats_text.append("<p><b>前10个UDP源端口:</b></p>")
                    self.stats_text.append("<ul>")
                    for port, count in sorted(udp_src_ports.items(), key=lambda x: x[1], reverse=True)[:10]:
                        self.stats_text.append(f"<li>{port}: {count} 个数据包 ({count/udp_count*100:.1f}%)</li>")
                    self.stats_text.append("</ul>")
                    
                    # UDP目标端口
                    udp_dst_ports = {}
                    for p in self.packets:
                        if UDP in p:
                            port = p[UDP].dport
                            udp_dst_ports[port] = udp_dst_ports.get(port, 0) + 1
                    
                    self.stats_text.append("<p><b>前10个UDP目标端口:</b></p>")
                    self.stats_text.append("<ul>")
                    for port, count in sorted(udp_dst_ports.items(), key=lambda x: x[1], reverse=True)[:10]:
                        self.stats_text.append(f"<li>{port}: {count} 个数据包 ({count/udp_count*100:.1f}%)</li>")
                    self.stats_text.append("</ul>")
            
            # TTL分布
            if any(IP in p for p in self.packets):
                self.stats_text.append("<h4>TTL分布</h4>")
                
                ttl_values = {}
                for p in self.packets:
                    if IP in p:
                        ttl = p[IP].ttl
                        ttl_values[ttl] = ttl_values.get(ttl, 0) + 1
                
                self.stats_text.append("<ul>")
                for ttl, count in sorted(ttl_values.items()):
                    self.stats_text.append(f"<li>TTL {ttl}: {count} 个数据包 ({count/total_packets*100:.1f}%)</li>")
                self.stats_text.append("</ul>")
            
            # 添加MAC地址统计
            if any(Ether in p for p in self.packets):
                self.stats_text.append("<h4>MAC地址统计</h4>")
                
                # 源MAC统计
                src_macs = {}
                for p in self.packets:
                    if Ether in p:
                        src_mac = p[Ether].src
                        src_macs[src_mac] = src_macs.get(src_mac, 0) + 1
                
                self.stats_text.append("<p><b>前10个源MAC地址:</b></p>")
                self.stats_text.append("<ul>")
                for mac, count in sorted(src_macs.items(), key=lambda x: x[1], reverse=True)[:10]:
                    self.stats_text.append(f"<li>{mac}: {count} 个数据包 ({count/total_packets*100:.1f}%)</li>")
                self.stats_text.append("</ul>")
                
                # 目标MAC统计
                dst_macs = {}
                for p in self.packets:
                    if Ether in p:
                        dst_mac = p[Ether].dst
                        dst_macs[dst_mac] = dst_macs.get(dst_mac, 0) + 1
                
                self.stats_text.append("<p><b>前10个目标MAC地址:</b></p>")
                self.stats_text.append("<ul>")
                for mac, count in sorted(dst_macs.items(), key=lambda x: x[1], reverse=True)[:10]:
                    self.stats_text.append(f"<li>{mac}: {count} 个数据包 ({count/total_packets*100:.1f}%)</li>")
                self.stats_text.append("</ul>")
            
            self.log("统计信息生成完成")
            
        except Exception as e:
            self.log(f"生成统计信息时出错: {str(e)}")
            QMessageBox.critical(self, "错误", f"生成统计信息时出错:\n{str(e)}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PCAPEditorGUI()
    sys.exit(app.exec_())