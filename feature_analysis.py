import math
import json
from collections import Counter
import pandas as pd
from tqdm import tqdm
from urllib.parse import urlparse, parse_qs
from config import Config, DataProcessor
from deepseek_analyzer import DeepSeekAnalyzer
import os
import glob
from pathlib import Path


class EnhancedFeatureAnalyzer:
    def __init__(self):
        self.analyzer = DeepSeekAnalyzer()
        self.system_prompt="""作为网络安全分析师，现在请基于以下流量的统计特征进行分析，判断是否属于攻击流量还是正常流量。如果是攻击，则可能是何种攻击手法；如果是正常，则解释为什么这些特征符合典型正常行为模式。

分析要求：

先结合统计特征区分正常流量和恶意流量：
正常流量典型特征：请求与响应次数大致匹配（比例接近1:1）、数据包大小稳定（低方差）、时间间隔均匀（无突发高峰）、整体低频次（非异常高请求率），符合标准协议行为如HTTP的交互模式。
恶意流量典型特征：请求次数远高于响应（可能表示DoS/DDoS或扫描）、异常高方差（大小或间隔波动大，表示注入或伪造）、极短时间间隔（高频洪泛）、不匹配的上/下行大小（例如上行异常大表示数据泄露或注入攻击）。
如果请求和响应只有一次，则基本排除DoS/DDoS类攻击，但仍检查其他异常如大小异常或间隔不合理。
判断是否存在攻击：如果特征符合正常模式，则返回“可能正常”并解释理由；如果存在异常，则继续分析，将统计模式与已知的攻击特征关联（如高请求率与DoS关联、异常大小与SQL注入或XSS关联）。
生成对于可能的攻击方式或异常方式的判断、详细解释（包括为什么这些统计特征指示该攻击）和关键描述（突出攻击的统计签名，如“高频小包洪泛”）。
生成漏洞搜索关键描述（对于前面的分析凝练成简短的几个词或短语，使用安全技术术语，如“DoS flood high-frequency requests”或“anomalous packet size injection”，用于RAG搜索；如果无攻击则为“无”）。
返回JSON格式包含：

statistical_analysis (str): 包含区分正常/恶意、判断、解释和关键描述的完整分析文本(适当精简)。
search_description (str): 简短的安全术语描述，用于搜索。
        """
        self.user_prompt_template = """
        - 基础特征:
        • 上行数据包大小: {u_avg_http_size}±{u_var_http_size:.1f} bytes
        • 下行数据包大小: {d_avg_http_size}±{d_var_http_size:.1f} bytes
        • 上行时间间隔: {u_avg_interval:.2f}±{u_var_interval:.2f} s
        • 下行时间间隔: {d_avg_interval:.2f}±{d_var_interval:.2f} s
        • 请求次数: {request_count} times
        • 响应次数: {response_count} times
        """

        self.required_fields = [
            'u_avg_http_size','u_var_http_size', 'd_avg_http_size',
            'd_var_http_size','u_avg_interval', 'u_var_interval',
            'd_avg_interval','d_var_interval',
            'request_count', 'response_count'
        ]

    def _preprocess_field(self, field_data):
        """预处理字段数据，确保是列表格式"""
        if isinstance(field_data, str):
            try:
                # 尝试解析JSON格式的字符串
                parsed = json.loads(field_data)
                if isinstance(parsed, dict):
                    # 如果是字典格式，转换为方法列表 (如 {'GET':6} -> ['GET','GET',...])
                    return [method for method, count in parsed.items() for _ in
                            range(count)]
                elif isinstance(parsed, list):
                    return parsed
                else:
                    return []
            except json.JSONDecodeError:
                # 如果是逗号分隔的字符串
                return [x.strip() for x in field_data.split(',') if x.strip()]
        elif isinstance(field_data, dict):
            # 直接处理字典输入
            return [method for method, count in field_data.items() for _ in
                    range(count)]
        elif isinstance(field_data, list):
            return field_data
        return []

    def _validate_row(self, row_data):
        """验证必要字段存在"""
        for field in self.required_fields:
            if field not in row_data:
                row_data[field] = 0
                print(f"⚠️ 字段 {field} 不存在，已设置默认值")
        return row_data

    def _enhance_data(self, row_data: dict) -> dict:
        """增强数据特征（保留原始列+新增分析列）"""
        try:
            # 1. 确保所有必需字段存在并预处理
            required_fields = {
                'u_avg_http_size': 0,
                'u_var_http_size': 0,
                'd_avg_http_size': 0,
                'd_var_http_size': 0,
                'u_var_interval': 0,
                'd_var_interval': 0,
                'd_avg_interval': 0,
                'u_avg_interval': 0,
                'request_count': 0,
                'response_count': 0,
                'status_codes': [],
            }

            # 设置默认值并预处理数据
            for field, default in required_fields.items():
                if field in row_data:
                    if field in ['status_codes']:
                        row_data[field] = self._preprocess_field(
                            row_data[field])
                    else:
                        row_data[field] = row_data.get(field, default)
                else:
                    row_data[field] = default

            # 3. 准备AI分析数据
            ai_input = {
                'u_avg_http_size': float(row_data['u_avg_http_size']),
                'd_avg_http_size': float(row_data['d_avg_http_size']),
                'u_var_http_size': float(row_data['u_var_http_size']),
                'u_var_interval': float(row_data['u_var_interval']),
                'u_avg_interval': float(row_data['u_avg_interval']),
                'd_var_http_size': float(row_data['d_var_http_size']),
                'd_var_interval': float(row_data['d_var_interval']),
                'd_avg_interval': float(row_data['d_avg_interval']),
                'request_count': float(row_data['request_count']),
                'response_count': float(row_data['response_count'])
            }


            # 4. 执行AI分析
            analysis_result = self.analyzer.analyze(
                system_prompt=self.system_prompt,
                user_prompt=self.user_prompt_template.format(**ai_input)
            )

            # 确保analysis_result是字典类型
            if not isinstance(analysis_result, dict):
                print(f"⚠️ 分析结果不是字典类型: {type(analysis_result)}")
                analysis_result = {
                    "statistical_analysis": "分析结果格式错误",
                    "search_description": []
                }

            # 5. 合并结果，添加raw_prompt和分析结果
            return {
                **row_data,
                **{f"{Config.ANALYSIS_COL_PREFIX}{k}": v for k, v in
                   analysis_result.items()}
            }
        except Exception as e:
            print(f"\n处理行时出错: {str(e)}")
            print(f"问题行数据: {row_data}")
            return {
                **row_data,
                f"{Config.ANALYSIS_COL_PREFIX}statistical_analysis": "处理错误",
                f"{Config.ANALYSIS_COL_PREFIX}search_description": "处理错误"
            }

    def analyze(self, input_dir: str, output_dir: str):
        """
        处理输入目录中的所有CSV文件，并在输出目录中生成对应的处理后的文件，保持编号一致

        参数:
            input_dir: 输入目录路径，包含要处理的CSV文件
            output_dir: 输出目录路径，用于保存处理后的CSV文件
        """
        # 确保输出目录存在
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # 获取输入目录中所有的CSV文件，并按编号排序
        input_files = sorted(glob.glob(os.path.join(input_dir, '*.csv')))

        # 使用tqdm显示进度条
        #for input_file in tqdm(input_files, desc="处理CSV文件"):
        for input_file in input_files:
            try:
                # 提取文件名和编号
                file_name = os.path.basename(input_file)
                file_stem = Path(input_file).stem

                # 假设文件名格式为"xxx_编号.csv"
                # 如果文件名中有多个下划线，我们取最后一部分作为编号
                file_parts = file_stem.split('_')
                if len(file_parts) > 1:
                    file_num = file_parts[-1]
                else:
                    file_num = "0"

                # 构建输出文件名，保持编号一致
                output_file = os.path.join(output_dir,
                                           f"feature_{file_num}.csv")

                # 读取CSV文件
                df = pd.read_csv(input_file, dtype={'status_codes': str})

                # 处理每一行数据
                results = []
                for _, row in df.iterrows():
                    enhanced_row = self._enhance_data(row.to_dict())
                    results.append(enhanced_row)

                # 保存处理后的数据
                pd.DataFrame(results).to_csv(output_file, index=False,
                                             encoding='utf-8-sig')

                print(
                    f"✅ 处理完成: {file_name} -> {os.path.basename(output_file)}")

            except Exception as e:
                print(f"❌ 处理文件 {file_name} 时出错: {str(e)}")
                continue