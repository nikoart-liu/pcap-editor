# PCAP编辑器

这是一个用于读取、修改和保存pcap文件的Python工具。它允许您修改数据包的各种属性，如源/目标IP地址、端口、TTL和TOS值等。

## 安装依赖

在使用此工具前，请确保已安装所需的依赖：

```bash
pip3 install scapy
```

## 使用方法

基本用法：

```bash
python3 pcap_editor.py -r input.pcap -w output.pcap [options]
```

### 可用选项

- `-r, --read`: 输入pcap文件路径（必需）
- `-w, --write`: 输出pcap文件路径（必需）
- `--src-ip`: 修改源IP地址（格式：原IP:新IP，例如：`--src-ip 192.168.1.1:10.0.0.1`）
- `--dst-ip`: 修改目标IP地址（格式：原IP:新IP，例如：`--dst-ip 192.168.1.2:10.0.0.2`）
- `--src-port`: 修改源端口（格式：原端口:新端口，例如：`--src-port 80:8080`）
- `--dst-port`: 修改目标端口（格式：原端口:新端口，例如：`--dst-port 80:8080`）
- `--ttl`: 修改TTL值（格式：原TTL:新TTL，例如：`--ttl 64:128`）
- `--tos`: 修改TOS值（格式：原TOS:新TOS，例如：`--tos 0:16`）
- `--offset`: 修改TCP/UDP数据包payload的偏移量（整数，例如：`--offset 10`）
- `--length`: 修改TCP/UDP数据包payload的长度（整数，例如：`--length 4`）
- `--data`: 修改TCP/UDP数据包payload的新值（十六进制字符串，例如：`--data AABBCCDD`）

## 示例

1. 修改源IP地址：

```bash
python3 pcap_editor.py -r input.pcap -w output.pcap --src-ip 192.168.1.1:10.0.0.1
```

2. 修改目标端口：

```bash
python3 pcap_editor.py -r input.pcap -w output.pcap --dst-port 80:8080
```

3. 同时修改多个属性：

```bash
python3 pcap_editor.py -r input.pcap -w output.pcap --src-ip 192.168.1.1:10.0.0.1 --dst-ip 192.168.1.2:10.0.0.2 --ttl 64:128
```

4. 使用偏移量和长度修改TCP/UDP报文的payload：

```bash
python3 pcap_editor.py -r input.pcap -w output.pcap --offset 10 --length 4 --data AABBCCDD
```

这个命令会修改所有TCP和UDP报文中payload的第10-13字节（从0开始计数），将其替换为十六进制值AABBCCDD。

## 注意事项

- 此工具仅修改与指定条件匹配的数据包
- 修改数据包后，校验和会自动重新计算
- 处理大型pcap文件可能需要较长时间