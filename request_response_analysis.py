import json
import os
import glob
from pathlib import Path
import pandas as pd
from tqdm import tqdm
from config import Config
from deepseek_analyzer import DeepSeekAnalyzer


class ContentAnalyzer:
    def __init__(self):
        self.analyzer = DeepSeekAnalyzer()

        # 系统提示词（固定不变）
        self.system_prompt = """作为一名网络安全专家，要对HTTP流量进行深入分析，通过请求和响应的完整内容来识别潜在的攻击模式，包括区分普通流量和恶意流量。分析时需首先解析请求中的域名，并检查域名与URL路径之间是否符合逻辑（例如，URL路径是否属于该域名下的正常服务路径）。针对IoT设备的流量，重点提取设备信息、版本型号、访问路径或特定文件名，用于精确匹配CVE描述；对于其他类型流量（如web应用、API或通用HTTP），提取可疑参数、路径、User-Agent或响应泄露，用于识别SQL注入、XSS、路径遍历等常见攻击，或异常行为以推断未知攻击。终极目标：在识别已知攻击（如CVE相关）的基础上，检测未知攻击，通过分析异常模式（如非标准格式、意外数据注入、响应异常泄露）来标记潜在新型威胁。

                检测要求：
        1. 先判断流量是否为普通（正常）流量：如果请求和响应符合标准HTTP规范、无可疑参数、无泄露敏感信息、无异常行为，正常用户是否会访问这个路径，且域名与URL路径之间符合逻辑（即URL路径属于该域名下的正常服务路径），则标记为普通流量并简要说明；否则标记为恶意或潜在恶意流量，并继续以下步骤。普通流量指无攻击迹象的常规访问，恶意流量包括已知攻击（如CVE利用）或未知异常（如畸形请求、意外注入）。
        2. 域名解析与URL路径符合性分析：解析请求中的Host头部（域名），并分析该域名与请求的URL路径之间是否符合逻辑（例如，对于CDN服务，特定路径可能是合法的；而对于普通企业网站，某些路径可能异常）。如果发现域名与路径不匹配（如请求的路径不属于该域名下的正常服务路径），则应视为可疑特征。
        3. 请求内容分析（请求方法是否异常、参数是否畸形或包含注入代码、格式是否不符合HTTP规范等；重点关注URL路径、User-Agent伪造、头部异常；针对IoT，提取设备相关路径如/devinfo或特定文件如info.cgi，无需带参数；针对其他类型，提取可疑路径如/admin或参数如id='1 OR 1=1，用于检测SQL注入或路径遍历）。
        4. 响应内容分析（是否有敏感文件/数据泄露、异常状态码、设备/服务器信息暴露、恶意重定向等；判断实现目的是否恶意，如返回 shell 输出表示命令注入；针对IoT，提取响应中设备型号如RT-N66U或品牌如hikvision；针对其他类型，提取泄露如数据库错误或服务器指纹，用于检测信息泄露或零日攻击）。
        5. 如果流量涉及IoT设备（基于路径如/cgi-bin/或User-Agent如IoT相关），提取request/response中出现的设备信息、版本、特定文件名或访问路径（完整原始形式，如组件list_base_config.php或访问路径/queryDevInfo），放入special_product列表中，用于CVE匹配；因为要想准确匹配cve，对于iot设备需要明确上述信息进行精准匹配才能实现,例如匹配CVE-2024-7339就是需要精准匹配iot访问路径/queryDevInfo，匹配CVE-2024-7120就是要精准匹配组件list_base_config.php；确保仅提取实际出现内容，非示例。
        6.注意区分正常流量和扫描流量（url的组成是否正常，域名是否包含url的路径，url路径是否是具有漏洞的常见路径，以及referer是否符合格式等）
        7. 针对未知攻击：如果分析中发现异常但不匹配已知模式（如畸形头部导致绕过、非标准编码注入、响应中意外二进制数据），在分析结果中明确标记为"潜在未知攻击"，并描述异常特征。
        8. 生成漏洞搜索关键描述（整合request/response分析，针对未知攻击，用"Anomalous Payload Injection"等描述；若无明显特征则为["无"]）。

        返回JSON格式包含：
        - is_normal (bool): 是否为普通流量（true为普通，false为恶意或潜在恶意）
        - request_analysis (str): 请求分析结果，包括是否涉及已知/未知攻击
        - response_analysis (str): 响应分析结果，包括是否涉及已知/未知攻击
        - rsearch_description (list): 漏洞搜索关键描述列表
        - special_product (list): 提取的特定文件名、设备型号、路径等（完整原始名字，若无则空列表）"""
        # 用户提示词模板（保持原有）
        self.user_prompt_template = """
请求内容:
{request}
响应内容:
{response}"""

    def _prepare_traffic_data(self, row):
        """提取请求/响应文本（保持不变）"""
        request = str(row.get('full_request', '')) if pd.notna(
            row.get('full_request')) else "无请求数据"
        response = str(row.get('full_response', '')) if pd.notna(
            row.get('full_response')) else "无响应数据"
        return request, response

    def _extract_file_number(self, file_stem: str) -> str:
        """从文件名提取编号（保持不变）"""
        parts = file_stem.split('_')
        return parts[-1] if len(parts) > 1 else "0"

    def analyze(self, input_dir: str, output_dir: str):
        """
        处理 input_dir 下所有 CSV，输出到 output_dir（主逻辑保持不变）
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        input_files = sorted(glob.glob(os.path.join(input_dir, '*.csv')))

        #for input_file in tqdm(input_files, desc="Content 流量分析"):
        for input_file in input_files:
            try:
                file_name = os.path.basename(input_file)
                file_stem = Path(input_file).stem
                file_num = self._extract_file_number(file_stem)
                output_file = os.path.join(output_dir,
                                           f"request_response_{file_num}.csv")

                df = pd.read_csv(input_file, dtype={'status_codes': str})
                results = []

                for _, row in df.iterrows():
                    row_data = row.to_dict()
                    request, response = self._prepare_traffic_data(row)

                    # 修改后的API调用方式
                    analysis_result = self.analyzer.analyze(
                        user_prompt=self.user_prompt_template.format(
                            request=request,
                            response=response
                        ),
                        system_prompt=self.system_prompt,
                        temperature=0.3,
                        max_tokens=3000
                    )

                    # 错误处理（保持原有字段结构）
                    if "error" in analysis_result:
                        row_data.update({
                            f"{Config.ANALYSIS_COL_PREFIX}error":
                                analysis_result["error"],
                            f"{Config.ANALYSIS_COL_PREFIX}raw_response": str(
                                analysis_result.get("raw_response", ""))
                        })
                    else:
                        row_data.update({
                            f"{Config.ANALYSIS_COL_PREFIX}is_normal": analysis_result.get(
                                'is_normal', True),
                            f"{Config.ANALYSIS_COL_PREFIX}request_analysis": analysis_result.get(
                                'request_analysis', ''),
                            f"{Config.ANALYSIS_COL_PREFIX}response_analysis": analysis_result.get(
                                'response_analysis', ''),
                            f"{Config.ANALYSIS_COL_PREFIX}rsearch_description": json.dumps(
                                analysis_result.get('rsearch_description', []),
                                ensure_ascii=False),
                            f"{Config.ANALYSIS_COL_PREFIX}special_product": json.dumps(
                                analysis_result.get('special_product', []),
                                ensure_ascii=False)
                        })

                    results.append(row_data)

                pd.DataFrame(results).to_csv(output_file, index=False,
                                             encoding='utf-8-sig')
                print(f"✅ 处理完成: {file_name} -> {os.path.basename(output_file)}")

            except Exception as e:
                print(f"❌ 处理文件 {file_name} 时出错: {e}")
                continue