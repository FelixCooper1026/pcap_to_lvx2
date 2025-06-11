# PCAP to LVX2 Converter

这是一个用于将 Livox 雷达的 PCAP 抓包文件转换为 LVX2 格式文件的 Python 脚本。

## 描述

本项目旨在提供一个高效且可靠的工具，将包含 Livox 雷达点云数据的 PCAP 文件转换为 Livox 官方 LVX2 文件格式。LVX2 文件是一种专有的文件格式，用于存储 Livox 雷达的点云数据及其相关信息，通常用于 Livox SDK 和上位机软件中。

该脚本通过手动解析原始 UDP 数据包，避免了 Scapy 库在协议解析上的性能开销，从而显著提高了大文件的处理速度。同时，它也包含了必要的错误处理机制，以确保数据完整性和用户反馈。

## 特性

*   **高效的数据包解析**：手动解析以太网、IP 和 UDP 头部，绕过 Scapy 的高层协议解析开销。
*   **LVX2 文件格式兼容**：严格按照 Livox LVX2 文件格式规范写入公共头、私有头、设备信息、帧头和数据包数据。
*   **设备信息自动提取与默认值**：尝试从 PCAP 文件中自动提取 Livox 雷达的设备信息；如果未找到，则使用默认的设备信息写入文件。
*   **文件预分配与缓冲写入**：通过文件预分配和内存缓冲写入技术，优化了大文件的写入性能，减少了磁盘 I/O。
*   **健壮的错误处理**：
    *   如果 PCAP 文件中未发现 56300 端口的点云数据，则在文件创建前立即报错并中止转换。
    *   处理时间戳解析错误，并使用默认值。
*   **进度条显示**：提供详细的转换进度条，包括数据包扫描和转换过程。

## 安装

在运行脚本之前，请确保您的系统上安装了 Python 3 和 Git。

1.  **克隆本仓库：**
    如果您还没有克隆项目，请使用以下命令将其克隆到本地：
    ```bash
    git clone https://github.com/YourUsername/YourRepoName.git # 请替换为您的实际仓库URL
    cd YourRepoName # 导航到项目目录
    ```

2.  **安装依赖：**
    使用 `pip` 安装所有必要的 Python 依赖：
    ```bash
    pip install -r requirements.txt
    ```

## 使用方法

```bash
python pcap_to_lvx2.py <输入PCAP文件路径> [输出LVX2文件路径]
```

*   `<输入PCAP文件路径>`：必填，您要转换的 PCAP 文件的路径。
*   `[输出LVX2文件路径]`：可选，生成的 LVX2 文件的路径。如果省略，脚本将默认在输入文件相同的目录下创建一个名为 `<输入文件名>.lvx2` 的文件。

**示例：**

将名为 `input.pcap` 的文件转换为 `output.lvx2`：
```bash
python pcap_to_lvx2.py input.pcap output.lvx2
```

使用默认输出文件名：
```bash
python pcap_to_lvx2.py my_data.pcap
```

## 错误处理示例

如果 PCAP 文件中不包含任何来自 56300 端口（Livox 雷达点云数据端口）的数据包，脚本将输出以下错误并终止，不会创建 LVX2 文件：

```
Error: No point cloud data found from port 56300 in the PCAP file. Aborting file creation.
```

## 依赖

本脚本依赖以下 Python 库，它们已在 `requirements.txt` 文件中列出：

*   `scapy`：用于读取 PCAP 文件并提取原始数据包。
*   `tqdm`：用于在控制台显示转换进度条。 