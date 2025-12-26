import os
import re
import logging
import warnings
import sys
import math
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Any, Iterator
import pandas as pd
from scapy.all import PcapReader, Raw
from concurrent.futures import ProcessPoolExecutor, as_completed
import time
from scapy.layers.inet import TCP, IP
import orjson  # 新增导入

# 配置日志
logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
warnings.filterwarnings("ignore")

# --- 正则表达式优化 ---
# 根据Python版本选择最优正则引擎
if sys.version_info >= (3, 11):
    try:
        from re._compiler import compile as re_compile
    except ImportError:
        re_compile = re.compile
else:
    try:
        import regex as re

        re_compile = re.compile
    except ImportError:
        re_compile = re.compile

# 预编译所有正则表达式
CONTENT_LENGTH_RE = re_compile(rb'Content-Length:\s*(\d+)', re.IGNORECASE)
CHUNKED_RE = re_compile(rb'Transfer-Encoding:\s*chunked', re.IGNORECASE)
USER_AGENT_RE = re_compile(rb'User-Agent:\s*(.+?)\r\n', re.IGNORECASE)
STATUS_CODE_RE = re_compile(rb'HTTP/\d(?:\.\d)?\s+(\d{3})')
HTTP_START_RE = re_compile(rb'HTTP/')
REQ_START_RE = re_compile(
    rb'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH)\s')
CHUNKED_END_MARKER = b'\r\n0\r\n\r\n'

CHECKPOINT_FILE = 'processing_checkpoint.json'  # 修改文件扩展名
CHUNK_SIZE = 1000
OUTPUT_CHUNK_SIZE = 5000  # 每10,000行输出一个文件


class ProcessingState:
    def __init__(self):
        self.processed_files = set()
        self.output_file_counter = 0  # 用于跟踪输出文件编号

    @classmethod
    def load(cls):
        if os.path.exists(CHECKPOINT_FILE):
            try:
                with open(CHECKPOINT_FILE, 'rb') as f:
                    data = orjson.loads(f.read())
                    state = cls()
                    state.processed_files = set(data['processed_files'])
                    state.output_file_counter = data['output_file_counter']
                    return state
            except Exception as e:
                logger.warning(f"加载检查点失败: {e}")
                return cls()
        return cls()

    def save(self):
        data = {
            'processed_files': list(self.processed_files),
            'output_file_counter': self.output_file_counter
        }
        with open(CHECKPOINT_FILE, 'wb') as f:
            f.write(orjson.dumps(data))


class HTTPStream:
    __slots__ = [
        'src_ip', 'dst_ip', 'src_port', 'dst_port',
        'u_packet_sizes', 'd_packet_sizes', 'u_intervals', 'd_intervals',
        'last_u_time', 'last_d_time', 'up_buffer', 'down_buffer',
        'stream_start', 'stream_end', 'first_request_content',
        'request_count', 'response_count', 'status_counts', 'sample_responses',
        # 新增: TCP流重组所需属性
        'up_expected_seq', 'down_expected_seq', 'up_out_of_order',
        'down_out_of_order',
        # 新增: HTTP层统计
        'u_http_payloads', 'd_http_payloads',
        # 新增: pcap文件来源
        'source_pcap'
    ]

    def __init__(self):
        self.src_ip, self.dst_ip, self.src_port, self.dst_port = (None,) * 4
        self.u_packet_sizes, self.d_packet_sizes, self.u_intervals, self.d_intervals = [], [], [], []
        self.last_u_time, self.last_d_time, self.stream_start, self.stream_end = None, None, None, None
        self.up_buffer, self.down_buffer = bytearray(), bytearray()
        self.first_request_content = None
        self.request_count = 0
        self.response_count = 0
        self.status_counts = defaultdict(int)
        self.sample_responses = {}
        # 新增: 初始化TCP序列号和乱序缓冲区
        self.up_expected_seq, self.down_expected_seq = None, None
        self.up_out_of_order, self.down_out_of_order = {}, {}
        # 新增: HTTP层统计
        self.u_http_payloads: List[int] = []
        self.d_http_payloads: List[int] = []
        # 新增: pcap文件来源
        self.source_pcap = ""

    def add_packet_meta(self, pkt_size: int, direction: str,
                        current_time: float):
        """只添加包的元数据，与TCP重组分离"""
        if direction == 'up':
            self.u_packet_sizes.append(pkt_size)
            if self.last_u_time:
                self.u_intervals.append(
                    current_time - self.last_u_time)
            self.last_u_time = current_time
        else:
            self.d_packet_sizes.append(pkt_size)
            if self.last_d_time:
                self.d_intervals.append(
                    current_time - self.last_d_time)
            self.last_d_time = current_time

        if self.stream_start is None:
            self.stream_start = current_time
        self.stream_end = current_time

    def add_tcp_segment(self, tcp_pkt: TCP, direction: str, pkt_time: float):
        """ 【核心修改】: 处理TCP段，实现可靠的流重组，支持首包处理、重叠、重传和乱序。 """
        seq = tcp_pkt.seq
        payload = bytes(tcp_pkt.payload)  # 统一转换为bytes
        payload_len = len(payload)
        added_data = False

        if direction == 'up':
            expected_seq = self.up_expected_seq
            ooo_buffer = self.up_out_of_order
            buffer = self.up_buffer
        else:
            expected_seq = self.down_expected_seq
            ooo_buffer = self.down_out_of_order
            buffer = self.down_buffer

        buffer_len_before = len(buffer)

        if expected_seq is None:
            # 处理第一个段: 假设它是流的起始
            expected_seq = seq
            if 'S' in tcp_pkt.flags:
                expected_seq += 1  # SYN消耗1个序列号
            if payload_len > 0:
                buffer.extend(payload)
                expected_seq += payload_len
                added_data = True
            logger.debug(f"初始化流 {direction}: expected_seq={expected_seq}")
        else:
            # 计算重叠
            overlap = expected_seq - seq
            if overlap >= payload_len:
                # 完全重传或旧段，忽略
                logger.debug(
                    f"忽略完全重传: SEQ={seq}, 期望={expected_seq}, len={payload_len}")
                return
            elif overlap > 0:
                # 部分重叠，截取新部分
                payload = payload[overlap:]
                seq += overlap
                payload_len = len(payload)
                logger.debug(f"处理部分重叠: 新SEQ={seq}, 新len={payload_len}")

            # 现在 seq >= expected_seq
            if seq == expected_seq:
                if payload_len > 0:
                    buffer.extend(payload)
                    expected_seq += payload_len
                    added_data = True

                # 冲刷乱序缓冲区
                while expected_seq in ooo_buffer:
                    buffered_payload = ooo_buffer.pop(expected_seq)
                    buffer.extend(buffered_payload)
                    expected_seq += len(buffered_payload)
                    added_data = True
            elif seq > expected_seq:
                # 乱序，存入缓冲
                if payload_len > 0 and seq not in ooo_buffer:
                    ooo_buffer[seq] = payload
                    logger.debug(f"存入乱序段: SEQ={seq}, len={payload_len}")
                return

        # 如果添加了数据，触发HTTP解析
        if added_data or len(buffer) > buffer_len_before:
            self.process_buffer(direction, pkt_time)

        # 更新期望序列号
        if direction == 'up':
            self.up_expected_seq = expected_seq
        else:
            self.down_expected_seq = expected_seq

    def _find_message_body_len(self, headers: bytes) -> Tuple[
        Optional[int], bool]:
        chunked_match = CHUNKED_RE.search(headers)
        if chunked_match:
            return None, True

        content_len_match = CONTENT_LENGTH_RE.search(headers)
        if content_len_match:
            return int(content_len_match.group(1)), False

        return 0, False

    def process_buffer(self, direction: str, pkt_time: float):
        """修改后的缓冲区处理方法，解决BufferError问题"""
        buffer = self.down_buffer if direction == 'down' else self.up_buffer
        start_re = HTTP_START_RE if direction == 'down' else REQ_START_RE
        pos = 0

        while pos < len(buffer):
            # 直接使用缓冲区切片进行搜索，不使用memoryview
            match = start_re.search(buffer[pos:])
            if not match:
                break

            rel_msg_start = match.start()
            abs_msg_start = pos + rel_msg_start
            abs_header_end = buffer.find(b'\r\n\r\n', abs_msg_start)
            if abs_header_end == -1:
                break

            try:
                headers = buffer[abs_msg_start: abs_header_end + 4]
                body_len, is_chunked = self._find_message_body_len(headers)
            except Exception as e:
                logger.warning(f"解析HTTP头时出错: {e}")
                pos += 1  # 跳过一个字节，避免无限循环
                continue

            if is_chunked:
                chunked_body_end = buffer.find(CHUNKED_END_MARKER,
                                               abs_header_end + 4)
                if chunked_body_end == -1:
                    break
                msg_len = chunked_body_end + len(
                    CHUNKED_END_MARKER) - abs_msg_start
            else:
                if body_len is None:
                    break
                msg_len = (abs_header_end - abs_msg_start + 4) + body_len

            if (abs_msg_start + msg_len) > len(buffer):
                break

            try:
                full_msg = buffer[abs_msg_start: abs_msg_start + msg_len]
                self._parse_http_message(full_msg, direction, pkt_time)
            except Exception as e:
                logger.warning(f"解析HTTP消息时出错: {e}")
                pos += 1  # 跳过一个字节，避免无限循环
                continue

            pos = abs_msg_start + msg_len

        # 使用新的缓冲区替换原始缓冲区，避免修改可能被引用的对象
        if pos > 0:
            if direction == 'down':
                self.down_buffer = self.down_buffer[pos:]
            else:
                self.up_buffer = self.up_buffer[pos:]

    def _parse_http_message(self, msg: bytes, direction: str, pkt_time: float):
        try:
            # 记录HTTP消息长度用于统计
            http_msg_len = len(msg)
            if direction == 'up':
                self.u_http_payloads.append(http_msg_len)
            else:
                self.d_http_payloads.append(http_msg_len)

            if direction == 'up':
                # 使用预编译的正则
                ua_match = USER_AGENT_RE.search(msg)
                user_agent = ua_match.group(1).decode('utf-8',
                                                      'ignore').strip() if ua_match else 'Unknown'

                # 优化第一行解析
                first_line_end = msg.find(b'\r\n')
                if first_line_end == -1:
                    return

                first_line = msg[:first_line_end].decode('utf-8',
                                                         'ignore').split()
                if len(first_line) < 2:
                    return

                self.request_count += 1

                if self.first_request_content is None:
                    self.first_request_content = self._clean_data(msg).decode(
                        'utf-8', 'replace')
            else:
                # 使用预编译的正则
                status_match = STATUS_CODE_RE.search(msg)
                if status_match:
                    code = status_match.group(1).decode('ascii')
                    self.status_counts[code] += 1
                    self.response_count += 1
                    if code not in self.sample_responses:
                        self.sample_responses[code] = self._clean_data(
                            msg).decode('utf-8', 'replace')
        except Exception as e:
            logger.error(f"解析HTTP消息时出错: {e}, 消息(部分): {msg[:150]}")

    @staticmethod
    def _clean_data(data: bytes) -> bytes:
        return bytes(b for b in data if 32 <= b <= 126 or b in {9, 10, 13})

    def _calculate_variance(self, data: List[float]) -> float:
        """计算数据的方差"""
        if not data or len(data) < 2:
            return 0.0

        n = len(data)
        mean = sum(data) / n
        variance = sum((x - mean) ** 2 for x in data) / (n - 1)
        return variance

    def _calculate_mean(self, data: List[float]) -> float:
        """计算数据的平均值"""
        if not data:
            return 0.0
        return sum(data) / len(data)

    def to_feature_dict(self) -> Dict[str, Any]:
        # 使用HTTP层数据进行统计
        u_packet_count = len(self.u_http_payloads)
        d_packet_count = len(self.d_http_payloads)
        u_interval_count = len(self.u_intervals)
        d_interval_count = len(self.d_intervals)

        # 计算HTTP层的平均值和方差
        u_avg_http_size = self._calculate_mean(self.u_http_payloads)
        d_avg_http_size = self._calculate_mean(self.d_http_payloads)
        u_var_http_size = self._calculate_variance(self.u_http_payloads)
        d_var_http_size = self._calculate_variance(self.d_http_payloads)

        # 时间间隔的统计（保持不变）
        u_avg_interval = self._calculate_mean(self.u_intervals)
        d_avg_interval = self._calculate_mean(self.d_intervals)
        u_var_interval = self._calculate_variance(self.u_intervals)
        d_var_interval = self._calculate_variance(self.d_intervals)

        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'u_avg_http_size': u_avg_http_size,
            'd_avg_http_size': d_avg_http_size,
            'u_var_http_size': u_var_http_size,
            'd_var_http_size': d_var_http_size,
            'u_avg_interval': u_avg_interval,
            'd_avg_interval': d_avg_interval,
            'u_var_interval': u_var_interval,
            'd_var_interval': d_var_interval,
            'stream_duration': (
                    self.stream_end - self.stream_start) if self.stream_end else 0.0,
            'request_count': self.request_count,
            'response_count': self.response_count,
            'status_codes': dict(self.status_counts),
            'full_request': self.first_request_content or '',
            'full_response': '\n\n'.join(self.sample_responses.values()),
            'source_pcap': self.source_pcap  # 添加pcap文件来源
        }


class PcapProcessor:
    def __init__(self):
        self.state = ProcessingState.load()
        self._records_buffer = []  # 新增: 用于批量写入的缓冲区

    def _get_direction(self, src_ip: str, src_port: int, dst_ip: str,
                       dst_port: int) -> Tuple[str, Tuple]:
        """ 根据端口号判断方向 """
        if src_port < dst_port:
            # 源端口是服务器端
            return 'down', (dst_ip, dst_port, src_ip, src_port)  # 下行: 服务器->客户端
        else:
            # 目标端口是服务器端或相等时(此时无法确定，默认源是客户端)
            return 'up', (src_ip, src_port, dst_ip, dst_port)  # 上行: 客户端->服务器

    def _process_packet(self, pkt, streams: Dict[Tuple, HTTPStream],
                        source_pcap: str = ""):
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return

        src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport

        # 判断方向和标准化流键
        direction, stream_key = self._get_direction(src_ip, src_port, dst_ip,
                                                    dst_port)

        if stream_key not in streams:
            stream = HTTPStream()
            # 总是按(客户端IP,客户端端口,服务器IP,服务器端口)顺序存储
            stream.src_ip, stream.src_port, stream.dst_ip, stream.dst_port = stream_key
            stream.source_pcap = source_pcap  # 记录来源pcap文件
            streams[stream_key] = stream

        stream = streams[stream_key]
        pkt_time = float(pkt.time)

        # 只统计携带TCP payload的包（过滤纯ACK等控制包）
        tcp_payload_len = len(pkt[TCP].payload)
        if tcp_payload_len > 0:
            stream.add_packet_meta(tcp_payload_len, direction, pkt_time)
            stream.add_tcp_segment(pkt[TCP], direction, pkt_time)

    def _process_single_file(self, filepath: str) -> List[Dict[str, Any]]:
        if filepath in self.state.processed_files:
            logger.info(f"跳过已处理文件: {filepath}")
            return []

        #logger.info(f"开始处理文件: {filepath}")
        start_time = time.time()
        streams: Dict[Tuple, HTTPStream] = {}

        try:
            with PcapReader(filepath) as pcap_reader:
                for pkt in pcap_reader:
                    self._process_packet(pkt, streams,
                                         os.path.basename(filepath))

            #logger.info(f"文件 {filepath} 读取完毕，开始处理残余缓冲区...")
            for stream in streams.values():
                if stream.up_buffer:
                    stream.process_buffer('up',
                                          stream.last_u_time or start_time)
                if stream.down_buffer:
                    stream.process_buffer('down',
                                          stream.last_d_time or start_time)

            result = [s.to_feature_dict() for s in streams.values() if
                      s.request_count or s.response_count]
            self.state.processed_files.add(filepath)
            self.state.save()

            #logger.info(f"完成处理: {filepath}, 耗时: {time.time() - start_time:.2f}s, 提取到 {len(result)} 条记录")
            return result
        except Exception as e:
            logger.error(f"处理文件 {filepath} 时出错: {e}", exc_info=True)
            return []

    def _write_batch(self, records: List[Dict[str, Any]], output_prefix: str):
        """批量写入记录到文件"""
        if not records:
            return

        chunk_counter = self.state.output_file_counter
        output_file = f"{output_prefix}_{chunk_counter}.csv"

        # 使用更高效的写入方式
        df = pd.DataFrame(records)
        df.to_csv(output_file, mode='w', header=True, index=False,
                  encoding='utf-8')

        #logger.info(f"已写入 {len(records)} 条记录到 {output_file}")
        self.state.output_file_counter = chunk_counter + 1
        self.state.save()

    def process_pcap_files(self, pcap_dir: str, output_prefix: str,
                           max_workers: int = 8) -> bool:
        """
        处理指定目录下的所有pcap文件

        参数:
            pcap_dir: 包含pcap文件的目录路径
            output_prefix: 输出文件的前缀路径(不要带扩展名)
            max_workers: 最大工作进程数

        返回:
            bool: 是否成功处理
        """
        try:
            # 获取所有pcap文件路径
            filepaths = [os.path.join(pcap_dir, fn) for fn in
                         os.listdir(pcap_dir)
                         if fn.lower().endswith(('.pcap', '.pcapng'))]

            if not filepaths:
                logger.warning(f"目录 {pcap_dir} 中没有找到pcap文件")
                return False

            # 确保输出目录存在
            output_dir = os.path.dirname(output_prefix)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)

            try:
                with ProcessPoolExecutor(max_workers=max_workers) as executor:
                    futures = {
                        executor.submit(self._process_single_file, fp): fp
                        for fp in filepaths}

                    batch_records = []
                    batch_size = 0

                    for future in as_completed(futures):
                        try:
                            records = future.result()
                            if records:  # 只处理有结果的记录
                                batch_records.extend(records)
                                batch_size += len(records)

                                # 当累积的记录达到阈值时，写入新文件
                                if batch_size >= OUTPUT_CHUNK_SIZE:
                                    self._write_batch(batch_records,
                                                      output_prefix)
                                    batch_records = []
                                    batch_size = 0
                        except Exception as e:
                            logger.error(
                                f"处理文件 {futures[future]} 时出错: {e}")
                            continue

                    # 处理剩余记录
                    if batch_records:
                        self._write_batch(batch_records, output_prefix)

                # 清理检查点文件
                if os.path.exists(CHECKPOINT_FILE):
                    try:
                        os.remove(CHECKPOINT_FILE)
                    except Exception as e:
                        logger.warning(f"删除检查点文件失败: {e}")

                #logger.info(f"所有数据处理完成，共生成 {self.state.output_file_counter} 个输出文件")
                return True

            except Exception as e:
                logger.error(f"处理过程中发生严重错误: {e}", exc_info=True)
                self.state.save()
                return False

        except Exception as e:
            logger.error(f"初始化处理时出错: {e}", exc_info=True)
            return False