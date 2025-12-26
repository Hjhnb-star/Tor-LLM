import glob
import json
import os
from pathlib import Path

import pandas as pd
from tqdm import tqdm
from deepseek_analyzer import DeepSeekAnalyzer
from config import Config, DataProcessor


class FeatureConsolidator:
    def __init__(self):
        self.analyzer = DeepSeekAnalyzer()
        self.analysis_prefix = Config.ANALYSIS_COL_PREFIX
        self.system_prompt="""作为网络安全专家，综合分析以下HTTP流量特征，包括区分普通流量和恶意流量。普通流量指所有特征（统计、内容、special_product）符合标准、无异常、无可疑关联的常规访问；恶意流量包括已知攻击（如CVE利用）或潜在未知攻击（如异常模式不匹配已知但显示注入/泄露/统计 outlier）。针对IoT设备流量，重点关联special_product中的设备信息、版本型号、访问路径或特定文件名，与统计/内容特征匹配CVE description（如路径/devinfo泄露设备型号）；对于其他类型流量（如web应用、API），关联可疑参数、User-Agent伪造、响应泄露或统计异常，生成具体描述如“SQL Injection via GET parameter”。终极目标：在识别已知攻击（如特征匹配CVE）的基础上，检测未知攻击，通过分析未匹配但异常的关联（如畸形参数+高频访问暗示新型注入）来标记潜在威胁，并在keywords中用描述如“Anomalous Payload in IoT Path”。请完成：

综合所有特征，先整体判断是否为普通流量：如果无异常关联（如正常统计+标准内容+无special_product），则attack_type为"Normal Traffic"，keywords为空列表，分析简要说明；否则分析可能的攻击类型或可疑行为模式，考虑特征之间的关联性（如IoT路径+响应泄露暗示设备探查，或web参数注入+统计高频暗示扫描），忽略无关信息；针对IoT，优先用special_product生成CVE-like描述；针对其他，提取可疑元素生成具体行为；若异常但不匹配已知，标记为"Potential Unknown Attack"并描述特征。
生成用于CVE检索的凝练关键描述，实现与RAG的语义embedding匹配（尽量用英文技术术语，并且用你的网页搜索能力仿照cve官方文档中的description的写法进行生成，例如CVE-2021-36260的description是：A command injection vulnerability in the web server of some Hikvision product. Due to the insufficient input validation, attacker can exploit the vulnerability to launch a command injection attack by sending some messages with malicious commands.），按照可能准确程度倒序排序（最匹配CVE description的先），不要生成太宽泛的描述，而是具体的行为描述；若正常或无明显，则为空列表；针对未知攻击，用具体异常描述如“Unusual Encoding Injection in Response”。
生成用于cwe检索的描述，仿照cwe官方文档的description的写法，根据流量特征生成相关描述。（例如：cwe-78的description是：The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.）
评估置信度（0-1），基于特征关联强度（e.g., 多维度匹配高置信，未知异常中置信）。
返回严格JSON格式：
{{
"attack_type": "攻击类型分类，如’Normal Traffic’、‘IoT Device Exploitation’、‘SQL Injection’或’Potential Unknown Attack",
"keywords"(str): "仿照cve的description生成的关键描述“,
"cwe_description"(str):"仿照cwe的description生成的关键描述“，
"confidence": 0.0,
"analysis": “综合给出判断的原因和分析，包括是否涉及未知攻击及依据”
}}
        """
        # 分析提示词模板
        self.user_prompt_template = """
统计特征
{stat_features}

###request和response的特征
{content_features}

###特定的文件或者设备类型
{special_product}
"""

    def _prepare_features(self, row):
        """准备各维度特征数据"""

        def safe_split(feature_str, sep="\n"):
            if pd.isna(feature_str) or feature_str is None:
                return []
            try:
                return str(feature_str).split(sep)
            except:
                return []

        return {
            "stat_features": f"- {row.get(f'{self.analysis_prefix}search_description', '')}",
            "content_features" : f"- {row.get(f'{self.analysis_prefix}rsearch_description', '')}",
            "special_product" : f"- {row.get(f'{self.analysis_prefix}special_product', '')}"
        }

    def consolidate(self, input_dir: str, output_dir: str):
        """
        处理 input_dir 下所有 csv，输出到 output_dir，文件名保持编号一致
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        input_files = sorted(glob.glob(os.path.join(input_dir, '*.csv')))

        #for input_csv in tqdm(input_files, desc="特征综合分析"):
        for input_csv in input_files:
            try:
                file_name = os.path.basename(input_csv)
                file_stem  = Path(input_csv).stem
                # 取最后一段作为编号
                file_num = file_stem.split('_')[-1] if '_' in file_stem else "0"
                output_csv = os.path.join(output_dir, f"consolidated_{file_num}.csv")

                df = pd.read_csv(input_csv)
                results = []

                for idx, row in df.iterrows():
                    row_data = row.to_dict()
                    try:
                        features = self._prepare_features(row)

                        analysis_result = self.analyzer.analyze(
                            system_prompt=self.system_prompt,
                            user_prompt=self.user_prompt_template.format(
                                **features)
                        )

                        row_data.update({
                            f"{self.analysis_prefix}attack_type": analysis_result.get("attack_type", ""),
                            f"{self.analysis_prefix}cve_keywords": analysis_result.get("keywords", ""),
                            f"{self.analysis_prefix}cwe_keywords": analysis_result.get("cwe_description",""),
                            f"{self.analysis_prefix}analysis_confidence": analysis_result.get("confidence", 0),
                            f"{self.analysis_prefix}consolidated_analysis": analysis_result.get("analysis", "")
                        })
                    except Exception as e:
                        row_data[f"{self.analysis_prefix}consolidation_error"] = str(e)[:200]
                        print(f"{file_name} 行 {idx+2} 失败: {e}")

                    results.append(row_data)

                pd.DataFrame(results).to_csv(output_csv, index=False, encoding='utf-8-sig')
                print(f"✅ 处理完成: {file_name} -> {os.path.basename(output_csv)}")

            except Exception as e:
                print(f"❌ 处理 {file_name} 时出错: {e}")
                continue