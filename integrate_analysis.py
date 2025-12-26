# ----------------- integrate_analysis.py -----------------
import glob
import os
from pathlib import Path

import pandas as pd
import json
from deepseek_analyzer import DeepSeekAnalyzer


class IntegrationAnalyzer:
    def __init__(self):
        self.analyzer = DeepSeekAnalyzer()
        self.system_prompt = """你是一位经验丰富的网络安全流量分析专家，需要你综合以下信息进行最终研判，包括区分普通流量和恶意流量。普通流量指符合标准HTTP规范、无可疑参数、无敏感泄露、无异常统计模式的常规访问；恶意流量包括已知攻击（如CVE利用）、潜在未知攻击（如异常注入、畸形格式、非标准行为导致的绕过或新型威胁）。针对IoT设备流量，重点综合设备信息、访问路径与CVE匹配；对于其他类型（如web应用、API），综合可疑参数、响应泄露与统计异常。终极目标：在识别已知攻击（如CVE相关特征）的基础上，检测未知攻击，通过分析异常模式（如非预期数据注入、统计 outlier、未匹配但可疑行为）来标记潜在新型威胁。

        首先根据前面的综合分析内容先判断是否为普通流量：如果所有维度（URL、User Agent、统计、request/response、CVE匹配）无明显异常，则标记为普通流量并简要说明；否则标记为恶意或潜在恶意流量，并继续以下步骤，借鉴下面分析思路检测：

        URL的语义特征（包括但不限于域名、路径、查询参数的含义和可能的恶意意图，如IoT路径/devinfo暗示设备探查，或web参数id=1’暗示注入）
        URL的结构特征（例如参数的复杂性、URL的长度、是否存在异常的编码等，如畸形URL导致解析异常，可能为未知绕过攻击）
        User Agent的特征（包括设备类型、浏览器类型、操作系统等信息，以及是否存在伪装或异常模式，如IoT UA伪造或非标准字符串暗示扫描）
        流量的统计特征（如访问频率、流量大小、连接持续时间等，是否存在异常的流量模式，如突发高频访问暗示DoS，或异常大小暗示数据外泄/注入）
        可能关联的CVE，需要你根据cve编号去查询相关描述，与流量特征相互对照，需要解释流量特征与cve文档内容是如何对应的（如路径匹配CVE中描述的漏洞端点）。如果对应程度并没有很好（e.g., 特征部分匹配但意图不符），考虑是否为未知攻击方式（e.g., 变种利用或零日攻击），并描述异常特征；CVE可能不全是准确的，若无匹配但有可疑，标记为潜在未知。
        request和response内容（请求的方法是否异常、参数是否畸形或包含注入代码、格式是否不符合规范等；响应是否有敏感文件泄露、异常状态码、设备/服务器信息暴露、恶意重定向等；判断实现目的是否恶意，如返回shell输出表示命令注入；针对IoT，综合提取的设备型号/路径与统计；针对其他类型，综合可疑元素如路径遍历或XSS payload与频率异常）
        是否是针对某些特别文件或者设备类型的攻击（e.g., IoT特定文件info.cgi或web敏感路径/admin，结合统计判断是否扫描/利用）
        针对未知攻击：如果综合分析发现异常（如统计 outlier + 非标准注入，但不匹配已知CVE），明确标记为“潜在未知攻击”，描述特征（如“异常编码注入可能绕过WAF”）。
        研判要求：

        确定最终风险等级（正常、中、高、未知）
        正常：未发现明显恶意特征或行为，综合所有维度无异常
        中风险：存在可疑特征，如轻微异常或部分CVE匹配，但无明确利用
        高风险：存在明确的恶意特征或行为，如强匹配CVE利用、敏感泄露、统计异常暗示攻击
        未知：分析结果不明确，无法确定风险等级，或疑似新型威胁无先例
        标记是否需要人工复核
        如果攻击手法或者意图不明确、存在不确定性（如CVE匹配弱或未知异常），建议人工复核
        如果置信度≥90（如多维度强证据），可标记为不需要人工复核
        明确攻击行为或意图
        描述可能的攻击行为（如“IoT设备信息泄露利用”或“SQL注入尝试”；针对未知，如“畸形参数注入绕过”）
        描述攻击意图（如“获取设备版本以进一步利用CVE”或“数据窃取”；针对未知，如“探查新型漏洞”）
        输出AI的综合分析内容
        详细描述AI对上述分析维度的综合判断，包括攻击行为、意图以及置信度的计算依据；若涉及未知攻击，明确说明异常模式及为什么不匹配已知
        分析内容应包含置信度计算逻辑（如：多维度强证据叠加得95分，单维度弱证据得60分）
        返回JSON格式包含以下字段：
        {
        “final_risk_level”: “正常/中/高/未知”,
        “attack_intent”: “攻击意图”,
        “needs_human_review”: true/false,
        “ai_analysis_content”: “AI的综合分析内容（需包含置信度计算逻辑）”,
        “confidence_level”: 90  # 0-100的整数，表示置信度百分比
        }"""

        self.user_prompt_template = """
综合分析内容如下：
{all_analysis}

"""

    def analyze(self, input_dir: str, output_dir: str):
        """目录级批量最终研判"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        input_files = sorted(glob.glob(os.path.join(input_dir, '*.csv')))

        for input_csv in input_files:
            try:
                file_name = os.path.basename(input_csv)
                file_stem  = Path(input_csv).stem
                file_num   = file_stem.split('_')[-1] if '_' in file_stem else "0"
                output_csv = os.path.join(output_dir, f"final_{file_num}.csv")

                df = pd.read_csv(input_csv)
                df['final_analysis'] = df.apply(self._generate_final_analysis, axis=1)

                df = pd.concat([
                    df,
                    df['final_analysis'].apply(lambda x: pd.Series(
                        self._parse_analysis_result(x) if pd.notna(x) else {
                            'final_risk_level': '未知',
                            'attack_intent': '未知',
                            'needs_human_review': True,
                            'ai_analysis_content': '分析失败',
                            'confidence_level': '低'
                        }
                    ))
                ], axis=1)

                df.to_csv(output_csv, index=False, encoding='utf-8-sig')
                print(f"✅ 最终研判完成: {file_name} -> {os.path.basename(output_csv)}")

            except Exception as e:
                print(f"❌ 处理 {file_name} 时出错: {e}")
                continue

    def _generate_final_analysis(self, row):
        """Generate the final analysis for each row"""
        '''
        URL语义分析: {row.get('analysis_url_semantic_analysis', '无')}
        URL结构分析：{row.get('analysis_parameter_and_Structural_analysis', '无')}
        UA分析: {row.get('analysis_ua_analysis', '无')}
        '''
        analysis_text = f"""

流量特征: {row.get('analysis_statistical_analysis', '无')}
可能的CVE：{row.get('analysis_reason','无')}
request内容分析：{row.get('analysis_request_analysis','无')}
response内容分析：{row.get('analysis_response_analysis','无')}

        """

        try:
            analysis_result = self.analyzer.analyze(
                system_prompt=self.system_prompt,
                user_prompt=self.user_prompt_template.format(
                    all_analysis=analysis_text)
            )
            return self._ensure_complete_result(analysis_result)
        except Exception as e:
            print(f"Analysis failed for row {row.name}: {str(e)}")
            return None

    def _ensure_complete_result(self, result):
        """确保返回结果包含所有必要字段"""
        if not isinstance(result, dict):
            try:
                result = json.loads(result) if isinstance(result, str) else {}
            except json.JSONDecodeError:
                result = {}

        default_result = {
            "final_risk_level": "未知",
            "attack_intent": "未知",
            "needs_human_review": True,
            "ai_analysis_content": "分析结果不完整",
            "confidence_level": "低"
        }

        return {**default_result, **result}

    def _parse_analysis_result(self, result):
        """Parse the analysis result into consistent format"""
        if isinstance(result, str):
            try:
                parsed = json.loads(result)
                return self._ensure_complete_result(parsed)
            except json.JSONDecodeError:
                return {
                    'final_risk_level': '高',
                    'attack_intent': '未知',
                    'needs_human_review': True,
                    'ai_analysis_content': result[:300],
                    'confidence_level': '低'
                }
        return self._ensure_complete_result(result)