import struct
from scapy.all import rdpcap, UDP, IP
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
import os
from tqdm import tqdm
import time
import socket
from collections import deque
import io


class PCAPToLVX2:
    def __init__(self, pcap_file, output_file=None):
        self.pcap_file = pcap_file
        if output_file is None:
            self.output_file = os.path.splitext(pcap_file)[0] + '.lvx2'
        else:
            self.output_file = output_file

        # 设置缓冲区大小（字节）
        self.buffer_size = 64 * 1024 * 1024  # 64MB buffer

        # LVX2文件头结构
        self.public_header = {
            'signature': 'livox_tech',  # 16字节
            'ver_a': 2,  # 1字节，固定为2
            'ver_b': 0,  # 1字节
            'ver_c': 0,  # 1字节
            'ver_d': 0,  # 1字节
            'magic_code': 0xAC0EA767  # 4字节
        }

        self.private_header = {
            'duration': 50,  # 4字节，单位ms，固定为50ms
            'device_count': 1  # 1字节
        }

        # 默认设备信息
        self.device_info = {
            'lidar_sn': 'DEFAULT_LIDAR',  # 16字节，使用固定前缀标识默认值
            'hub_sn': 'DEFAULT_HUB',  # 16字节，使用特殊前缀
            'lidar_id': 0,  # 4字节
            'lidar_type': 247,  # 1字节，根据上位机录制文件，Device Info中为247
            'device_type': 9,  # 1字节，固定为9
            'enable_extrinsic': 0,  # 1字节
            'offset_roll': 0.0,  # 4字节
            'offset_pitch': 0.0,  # 4字节
            'offset_yaw': 0.0,  # 4字节
            'offset_x': 0.0,  # 4字节
            'offset_y': 0.0,  # 4字节
            'offset_z': 0.0  # 4字节
        }

        # 帧相关变量
        self.frame_index = 0
        self.current_offset = 0
        self.frame_packages = deque(maxlen=1000)  # 使用deque限制内存使用
        self.ns_threshold = 50_000_000  # 50ms (固定为50毫秒)

    @staticmethod
    def parse_raw_udp_packet(pkt_data):
        """Manually parses raw packet data to extract UDP payload and ports."""
        try:
            # Ethernet Header (14 bytes)
            if len(pkt_data) < 14:
                return None, None, None
            eth_type = struct.unpack('>H', pkt_data[12:14])[0]
            if eth_type != 0x0800:  # Not IP (IPv4)
                return None, None, None

            # IP Header
            ip_header_start = 14
            if len(pkt_data) < ip_header_start + 1:
                return None, None, None
            ip_ihl = (pkt_data[ip_header_start] & 0x0F) * 4  # IHL in 4-byte words
            if len(pkt_data) < ip_header_start + ip_ihl:
                return None, None, None

            ip_protocol = pkt_data[ip_header_start + 9]  # Protocol field (byte 9)
            if ip_protocol != 17:  # Not UDP (UDP protocol number is 17)
                return None, None, None

            # UDP Header
            udp_header_start = ip_header_start + ip_ihl
            if len(pkt_data) < udp_header_start + 8:  # UDP header is 8 bytes
                return None, None, None

            udp_src_port = struct.unpack('>H', pkt_data[udp_header_start:udp_header_start + 2])[0]
            udp_dst_port = struct.unpack('>H', pkt_data[udp_header_start + 2:udp_header_start + 4])[0]

            udp_payload = pkt_data[udp_header_start + 8:]

            return udp_payload, udp_src_port, udp_dst_port
        except Exception:
            return None, None, None

    def parse_udp_payload(self, payload):
        """解析雷达 UDP payload 数据"""
        index = 28
        data_dict = {}

        while index < len(payload):
            if index + 2 > len(payload):
                break

            # 解析参数编号（Key）
            key = struct.unpack_from("<H", payload, index)[0]
            index += 2

            # 解析参数长度
            length = struct.unpack_from("<H", payload, index)[0]
            index += 2

            # 提取数据
            data_bytes = payload[index: index + length]
            index += length

            # 解析设备信息相关字段
            if key == 0x8000:  # SN 号
                sn = data_bytes.decode('utf-8').rstrip('\x00')
                self.device_info['lidar_sn'] = sn.ljust(16, '\0')

            elif key == 0x0004:  # lidar_ipcfg (雷达IP配置)
                ip = ".".join(map(str, data_bytes[:4]))
                self.device_info['lidar_id'] = self.ip_to_lidar_id(ip)
                print(f"Found LiDAR IP: {ip}, lidarID: {self.device_info['lidar_id']}")

            elif key == 0x0012:  # install_attitude (外参配置)
                roll, pitch, yaw = struct.unpack_from("<fff", data_bytes, 0)
                x, y, z = struct.unpack_from("<iii", data_bytes, 12)
                self.device_info['enable_extrinsic'] = 1
                self.device_info['offset_roll'] = roll
                self.device_info['offset_pitch'] = pitch
                self.device_info['offset_yaw'] = yaw
                self.device_info['offset_x'] = x / 1000.0  # 转换为米
                self.device_info['offset_y'] = y / 1000.0  # 转换为米
                self.device_info['offset_z'] = z / 1000.0  # 转换为米

    def extract_device_info(self, all_raw_packets):
        """从PCAP文件中提取设备信息"""
        print("Extracting device information from PCAP file...")
        info_extracted = False
        try:
            for pkt_data in all_raw_packets:
                try:
                    payload, src_port, dst_port = PCAPToLVX2.parse_raw_udp_packet(pkt_data)
                    if payload is None:  
                        continue

                    # 检查是否是 Mid-360 设备信息数据包（端口56200）
                    if src_port == 56200 or dst_port == 56200:
                        self.parse_udp_payload(payload)
                        # 如果已经获取到SN号，说明基本信息已经获取完成
                        if self.device_info['lidar_sn'] and self.device_info['lidar_sn'] != 'DEFAULT_LIDAR':
                            print(f"Extracted LiDAR SN: {self.device_info['lidar_sn']}")
                            info_extracted = True
                            break
                except Exception as e:
                    # print(f"Error processing device info packet: {e}") # Comment out for cleaner output
                    continue
        except Exception as e:
            print(f"An unexpected error occurred during device info extraction: {e}")
            return False

        if not info_extracted:
            print("No device information found from port 56200.")
        return info_extracted

    def write_headers(self, f):
        # 写入公共头 (24字节)
        # 写入签名 (16字节)
        signature = self.public_header['signature'].encode('utf-8')
        f.write(signature.ljust(16, b'\0'))
        # 写入版本号 (4字节)
        f.write(struct.pack('<BBBB',
                            self.public_header['ver_a'],
                            self.public_header['ver_b'],
                            self.public_header['ver_c'],
                            self.public_header['ver_d']))
        # 写入魔术码 (4字节)
        f.write(struct.pack('<I', self.public_header['magic_code']))

        # 写入私有头 (5字节)
        # 写入记录时长 (4字节)
        f.write(struct.pack('<I', self.private_header['duration']))
        # print(f"[DEBUG_HDR] Private Header - Duration: {self.private_header['duration']} ms")
        # 写入设备数量 (1字节)
        f.write(struct.pack('<B', self.private_header['device_count']))
        # print(f"[DEBUG_HDR] Private Header - Device Count: {self.private_header['device_count']}")

        # 写入设备信息 (63字节)
        # 写入LiDAR SN (16字节)
        lidar_sn_bytes = self.device_info['lidar_sn'].encode('utf-8').ljust(16, b'\0')
        f.write(lidar_sn_bytes)
        # print(f"[DEBUG_HDR] Device Info - LiDAR SN: {self.device_info['lidar_sn']} (bytes: {lidar_sn_bytes.hex()})")
        # 写入Hub SN (16字节)
        hub_sn_bytes = self.device_info['hub_sn'].encode('utf-8').ljust(16, b'\0')
        f.write(hub_sn_bytes)
        # print(f"[DEBUG_HDR] Device Info - Hub SN: {self.device_info['hub_sn']} (bytes: {hub_sn_bytes.hex()})")
        # 写入LiDAR ID (4字节)
        f.write(struct.pack('<I', self.device_info['lidar_id']))
        # print(f"[DEBUG_HDR] Device Info - LiDAR ID: {self.device_info['lidar_id']}")
        # 写入LiDAR类型 (1字节)
        f.write(struct.pack('<B', self.device_info['lidar_type']))
        # print(f"[DEBUG_HDR] Device Info - LiDAR Type: {self.device_info['lidar_type']}")
        # 写入设备类型 (1字节)
        f.write(struct.pack('<B', self.device_info['device_type']))
        # print(f"[DEBUG_HDR] Device Info - Device Type: {self.device_info['device_type']}")
        # 写入是否启用外参 (1字节)
        f.write(struct.pack('<B', self.device_info['enable_extrinsic']))
        # print(f"[DEBUG_HDR] Device Info - Enable Extrinsic: {self.device_info['enable_extrinsic']}")
        # 写入外参 (24字节)
        f.write(struct.pack('<ffffff',
                            self.device_info['offset_roll'],
                            self.device_info['offset_pitch'],
                            self.device_info['offset_yaw'],
                            self.device_info['offset_x'],
                            self.device_info['offset_y'],
                            self.device_info['offset_z']))
        # print(f"[DEBUG_HDR] Device Info - Extrinsic: Roll={self.device_info['offset_roll']}, Pitch={self.device_info['offset_pitch']}, Yaw={self.device_info['offset_yaw']}, X={self.device_info['offset_x']}, Y={self.device_info['offset_y']}, Z={self.device_info['offset_z']}")

    def get_timestamp_from_payload(self, payload):
        """从UDP包的payload中获取时间戳"""
        try:
            if len(payload) >= 36:  # 确保payload长度足够
                timestamp_bytes = payload[28:36]  # 时间戳在payload中的位置
                if len(timestamp_bytes) == 8:
                    return struct.unpack('<Q', timestamp_bytes)[0]
            return None
        except Exception as e:
            print(f"Warning: Error getting timestamp from payload: {e}")
            return None

    def ip_to_lidar_id(self, ip_str):
        """将IP地址转换为lidarID"""
        try:
            # 将IP地址转换为32位整数
            ip_int = struct.unpack('!I', socket.inet_aton(ip_str))[0]
            return ip_int
        except Exception as e:
            print(f"Error converting IP to lidarID: {e}")
            return 0

    def write_frame_header(self, f, frame_size):
        """写入帧头"""
        # 计算下一帧的偏移量
        next_offset = self.current_offset + 24 + frame_size  # 24是帧头大小

        # 写入帧头 (24字节)
        f.write(struct.pack('<Q', self.current_offset))  # current_offset
        f.write(struct.pack('<Q', next_offset))  # next_offset
        f.write(struct.pack('<Q', self.frame_index))  # frame_index

        # 更新偏移量和帧索引
        self.current_offset = next_offset
        self.frame_index += 1

    def write_package_header(self, raw_udp_payload: bytes, data_length: int) -> bytes:
        """构建LVX2数据包头并返回字节序列 (27字节)
           从原始UDP payload中提取对应字段，并根据LVX2格式写入。
        """
        pkg_header_bytes = bytearray()

        # 1. version (1 byte, LVX2 offset 0, from UDP payload offset 0)
        version_val = struct.unpack('<B', raw_udp_payload[0:1])[0]
        pkg_header_bytes.extend(struct.pack('<B', version_val))
        # print(f"[DEBUG_PKG_HDR]  Version: {version_val}") # Re-enable if needed for future debug

        # 2. lidar_id (4 bytes, LVX2 offset 1, from self.device_info)
        pkg_header_bytes.extend(struct.pack('<I', self.device_info['lidar_id']))
        # print(f"[DEBUG_PKG_HDR]  LiDAR ID: {self.device_info['lidar_id']}") # Re-enable if needed for future debug

        # 3. lidar_type (1 byte, LVX2 offset 5) - Hardcoded to 8 for Package Header as per recorded file
        pkg_header_bytes.extend(struct.pack('<B', 8))  # Hardcode to 8 as per recorded file's Package Header
        # print(f"[DEBUG_PKG_HDR]  LiDAR Type: {8}") # Re-enable if needed for future debug

        # 4. timestamp_type (1 byte, LVX2 offset 6, from UDP payload offset 11)
        timestamp_type_val = struct.unpack('<B', raw_udp_payload[11:12])[0]
        pkg_header_bytes.extend(struct.pack('<B', timestamp_type_val))
        # print(f"[DEBUG_PKG_HDR]  Timestamp Type: {timestamp_type_val}") # Re-enable if needed for future debug

        # 5. timestamp (8 bytes, LVX2 offset 7, from UDP payload offset 28)
        timestamp_val = struct.unpack('<Q', raw_udp_payload[28:36])[0]
        pkg_header_bytes.extend(struct.pack('<Q', timestamp_val))
        # print(f"[DEBUG_PKG_HDR]  Timestamp: {timestamp_val}") # Re-enable if needed for future debug

        # 6. udp_count (2 bytes, LVX2 offset 15, from UDP payload offset 7)
        udp_count_val = struct.unpack('<H', raw_udp_payload[7:9])[0]
        pkg_header_bytes.extend(struct.pack('<H', udp_count_val))
        # print(f"[DEBUG_PKG_HDR]  UDP Count: {udp_count_val}") # Re-enable if needed for future debug

        # 7. data_type (1 byte, LVX2 offset 17, from UDP payload offset 10)
        data_type_val = struct.unpack('<B', raw_udp_payload[10:11])[0]
        pkg_header_bytes.extend(struct.pack('<B', data_type_val))
        # print(f"[DEBUG_PKG_HDR]  Data Type: {data_type_val}") # Re-enable if needed for future debug

        # 8. length (4 bytes, LVX2 offset 18, point data length)
        # This is the length of the actual point cloud data section (raw_udp_payload[36:])
        pkg_header_bytes.extend(struct.pack('<I', data_length))
        # print(f"[DEBUG_PKG_HDR]  Data Length (points): {data_length}") # Re-enable if needed for future debug

        # 9. frame_count (1 byte, LVX2 offset 22, from UDP payload offset 9)
        frame_count_val = struct.unpack('<B', raw_udp_payload[9:10])[0]
        pkg_header_bytes.extend(struct.pack('<B', frame_count_val))
        # print(f"[DEBUG_PKG_HDR]  Frame Count (in package): {frame_count_val}") # Re-enable if needed for future debug

        # 10. reserved (4 bytes, LVX2 offset 23, all zeros)
        pkg_header_bytes.extend(b'\0' * 4)

        return bytes(pkg_header_bytes)

    def convert(self):
        print(f"Converting {self.pcap_file} to {self.output_file}")

        # 首先读取所有数据包到内存中
        print("Reading all PCAP packets into memory...")
        all_raw_packets = [pkt_data for pkt_data, _ in RawPcapReader(self.pcap_file)]
        total_packets = len(all_raw_packets)
        print(f"Total packets read into memory: {total_packets}")

        # 首先提取设备信息
        device_info_extracted = self.extract_device_info(all_raw_packets)
        if not device_info_extracted:
            print("Warning: 未获取到56200端口设备信息，将使用默认设备信息写入LVX2文件。")

        # 在打开文件前，预扫描以检查是否存在56300端口的点云数据
        point_data_found = False
        print("Pre-scanning packets for 56300 port data...")
        for pkt_data in tqdm(all_raw_packets, desc="Pre-scanning"):  # Use a separate tqdm for pre-scan
            _, src_port, _ = PCAPToLVX2.parse_raw_udp_packet(pkt_data)
            if src_port == 56300:
                point_data_found = True
                break

        if not point_data_found:
            raise RuntimeError(
                "Error: No point cloud data found from port 56300 in the PCAP file. Aborting file creation.")

        # 使用内存映射文件进行写入
        with open(self.output_file, 'wb') as f:
            # 预分配文件空间（假设每个包平均1KB）
            f.seek(total_packets * 1024 - 1)
            f.write(b'\0')
            f.seek(0)

            # 写入文件头
            self.write_headers(f)

            # 初始化帧相关变量
            self.frame_index = 0
            self.current_offset = 92  # 24(公共头) + 5(私有头) + 63(设备信息)
            self.frame_packages.clear()
            last_timestamp = None

            # 使用缓冲写入
            buffer = io.BytesIO()
            buffer_size = 0

            # 处理数据包
            with tqdm(total=total_packets, desc="Converting") as pbar:
                for pkt_data in all_raw_packets:  
                    try:
                        payload, src_port, dst_port = PCAPToLVX2.parse_raw_udp_packet(pkt_data)
                        if payload is None:  
                            continue

                        if src_port == 56300:  # Mid-360 点云数据端口
                            if len(payload) >= 28:
                                timestamp = self.get_timestamp_from_payload(payload)
                                if timestamp is not None:
                                    # 检查是否需要创建新帧
                                    if last_timestamp is None or timestamp - last_timestamp >= self.ns_threshold:
                                        # 如果有待写入的包，先写入当前帧
                                        if self.frame_packages:
                                            frame_size = sum(len(pkg) for pkg in self.frame_packages)
                                            self.write_frame_header(buffer, frame_size)
                                            for pkg in self.frame_packages:
                                                buffer.write(pkg)
                                            buffer_size += 24 + frame_size  # 24是帧头大小

                                            # 如果缓冲区达到阈值，写入文件
                                            if buffer_size >= self.buffer_size:
                                                f.write(buffer.getvalue())
                                                buffer = io.BytesIO()
                                                buffer_size = 0

                                            self.frame_packages.clear()

                                        last_timestamp = timestamp

                                    # 准备数据包头
                                    data = payload[36:]  # 跳过UDP头部（36字节）
                                    data_length = len(data)

                                    # 创建LVX2数据包
                                    pkg = bytearray()
                                    package_header_bytes = self.write_package_header(payload, data_length)
                                    pkg.extend(package_header_bytes)
                                    pkg.extend(data)

                                    # 添加到当前帧
                                    self.frame_packages.append(bytes(pkg))
                    except Exception as e:
                        continue

                    pbar.update(1)

            # 写入最后一帧
            if self.frame_packages:
                frame_size = sum(len(pkg) for pkg in self.frame_packages)
                self.write_frame_header(buffer, frame_size)
                for pkg in self.frame_packages:
                    buffer.write(pkg)

            # 写入剩余的缓冲区数据
            if buffer_size > 0:
                f.write(buffer.getvalue())

        print(f"Conversion completed. Output file: {self.output_file}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Convert PCAP file to LVX2 format")
    parser.add_argument('input_file', help='Input PCAP file path')
    parser.add_argument('output_file', nargs='?', help='Output LVX2 file path (optional)')

    args = parser.parse_args()

    converter = PCAPToLVX2(args.input_file, args.output_file)
    converter.convert()


if __name__ == "__main__":
    main()