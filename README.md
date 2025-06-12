# PCAP 转 LVX2 转换工具

一个用于将 Livox 激光雷达 PCAP 文件转换为 LVX2 格式的 Python 工具。

## 简介

本工具可以高效地将包含 Livox 激光雷达点云数据的 PCAP 文件转换为官方 LVX2 格式，后者可使用官方上位机软件 Livox Viewer2 直接读取并进行可视化播放。

## 特性

- 快速数据包解析，手动处理 UDP/IP header
- 完整的 LVX2 文件格式兼容性
- 自动提取设备信息，支持默认值回退
- 优化的文件 I/O，支持预分配和缓冲写入
- 鲁棒的错误处理和验证机制
- 实时处理进度、速度及预估剩余时间显示

## 安装

```bash
# 克隆仓库
git clone https://github.com/FelixCooper1026/pcap_to_lvx2.git

# 安装依赖
pip install -r requirements.txt
```

## 使用方法

```bash
python pcap_to_lvx2.py <输入文件> [输出文件]
```

### 参数说明

- `输入文件`：PCAP 文件路径（必需）
- `输出文件`：LVX2 文件路径（可选，默认为 `<输入文件名>.lvx2`）

### 使用示例

```bash
# 指定输出文件
python pcap_to_lvx2.py input.pcap output.lvx2

# 使用默认输出文件名
python pcap_to_lvx2.py input.pcap
```

## 错误处理

工具会对输入 pcap 数据进行验证并提供清晰的错误提示。例如，输入 pcap 文件中不包含任何 Livox 激光雷达点云数据时：

```
Error: No point cloud data found from port 56300 in the PCAP file. Aborting file creation.
```

## 依赖项

- scapy：用于读取 PCAP 文件
- tqdm：用于显示进度条

## 许可证

本项目采用 BSD-3-Clause 许可证。详情请参阅 [LICENSE](LICENSE) 文件。
