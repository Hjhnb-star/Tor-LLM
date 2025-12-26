import json
import os
import glob
import re
from pathlib import Path
from datetime import datetime
from dateutil.parser import parse
import pandas as pd
from tqdm import tqdm
from neo4j import GraphDatabase
from langchain_ollama import OllamaEmbeddings
from config import Config
from deepseek_analyzer import DeepSeekAnalyzer
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

class Neo4jCVEAnalyzer:
    def __init__(self):
        """Initialize Neo4j connection and embedding model"""
        self.driver = GraphDatabase.driver(
            Config.NEO4J_URI,
            auth=(Config.NEO4J_USER, Config.NEO4J_PASSWORD)
        )
        self.embeddings = OllamaEmbeddings(model=Config.EMBEDDING_MODEL)
        self.embedding_dimensions = Config.EMBEDDING_DIMENSIONS
        self.analysis_prefix = Config.ANALYSIS_COL_PREFIX
        self.analyzer = DeepSeekAnalyzer()

        # Configuration parameters
        self.top_k_cwe = 3
        self.top_k_cve = 10
        self.similarity_threshold = 0.3
        self.max_keyword_results_per_term = 7  # Max CVEs to return per keyword
        self.system_prompt = """
                        您是一位网络安全威胁分析专家，专注于使用CVE漏洞评估网络流量中的潜在恶意攻击。您的任务是基于设备组件关键词、流量特征和用户提供的CVE组进行威胁评估，需特别注意避免产品范围误匹配问题。

                        分析要求：
                        0. 流量类型判定与策略选择：
                           - IoT流量判定：产品关键词包含IoT特定元素（如设备型号/组件名如list_base_config.php或路径/queryDevInfo）
                           - 非IoT流量判定：产品关键词缺乏IoT特定术语（仅通用协议/无设备路径提及）

                           IoT流量分析策略：
                           - 匹配优先级：访问路径 > 组件名 > 产品型号 > 语义相似度
                           - 关键词完全匹配优先：即使语义稍弱，只要产品关键词在CVE描述中完全匹配即优先选择（如CVE-2024-7339含/queryDevInfo）

                           非IoT流量分析策略：
                           - 双重校验机制：
                             1. 语义相似性校验：流量特征与CVE描述的漏洞模式是否匹配（如路径遍历、注入等）
                             2. 产品适用性校验：检查CVE描述是否限定特定产品范围
                               * 若CVE描述明确提及特定产品（如"Affected: Apache Tomcat"），则必须验证当前流量特征包含该产品关键词
                               * 若CVE描述为通用漏洞模式（如"Directory traversal in web applications"），则允许匹配
                           - 匹配优先级：产品适用性 > 语义相似度 > 发布日期

                        1. CVE分析（仅基于用户提供）：
                           - 仅分析用户提供的CVE列表，不进行任何外部搜索。
                           - 对于每个提供的CVE，详细分析其描述、受影响产品范围、利用细节与当前流量特征的匹配度。
                           - 分析时仔细验证每个CVE的description是否真的符合用户提供的流量场景：
                             - 对于IoT流量：验证产品/组件/路径是否完全符合（例如，CVE必须针对相同的设备类型或路径，而非类似但不同产品的漏洞）。
                             - 对于非IoT流量：验证是否合适，不要只是语义相似（如关键词匹配），而是要确保CVE针对该流量场景的通用漏洞模式，而非限定于某一特定产品（如果CVE是产品特定的，必须检查是否与流量特征匹配，否则排除）。
                             - 排除仅语义相似但不针对该流量场景的CVE（例如，避免将针对特定软件的漏洞误匹配到通用HTTP流量）。

                        2. CVE匹配验证：
                           - 从用户提供的cve_matches组中，选择1-2个最佳匹配CVE。
                           - 对于所有提供的CVE：
                             - IoT流量：产品关键词完全匹配（路径/组件/型号）即优先选择，语义作为补充。仔细分析description是否真的符合产品完全匹配，而非部分相似。
                             - 非IoT流量执行双重验证：
                               ```python
                               if CVE描述包含特定产品范围:
                                   if 当前流量特征包含该产品关键词:
                                       进入语义匹配验证
                                   else:
                                       排除该CVE（避免产品范围误报）
                               else:  # 通用漏洞模式
                                   进行语义相似度分析
                               ```
                             - 语义相似度需结合上下文：不仅是关键词匹配，还要验证攻击手法与流量特征的契合度（如路径遍历的参数位置/编码方式）。确保非IoT场景下CVE合适，而非针对特定产品但不适用于该流量。

                        3. 威胁评估：
                           - 从用户提供的cve_matches中，选择1-2个最佳匹配CVE（基于上述验证和优先级）。
                           - 攻击类型需明确标注：IoT设备特定攻击/通用漏洞攻击
                           - 置信度评分（0.0-1.0）依据：
                             * IoT流量：产品匹配度 + 语义相似度
                             * 非IoT流量：产品适用性验证结果 + 语义契合度 + 上下文一致性
                             

                        严格以JSON格式返回：
                        {
                            "matched_cves": [
                                {
                                    "id": "CVE-ID",
                                    "confidence": 0.0,
                                    "match_reason": "详细说明产品关键词匹配情况（IoT）或产品适用性验证结果（非IoT），语义相似度分析，上下文契合度，包括比较择优依据"
                                }
                            ],
                            "attack_type": "攻击类型（需标注'IoT设备特定攻击'或'通用漏洞攻击'）",
                            "overall_confidence": 0.0,
                            "reason": "完整说明：流量类型判定、CVE分析过程、匹配策略、双重验证过程（非IoT）、排除误报的依据，以及从提供的cve_matches中选择最佳匹配的过程"
                        }
                        """

        self.user_prompt_template = """
    ### 产品关键词（例如，IoT设备、组件、型号）
    {product_keywords}

    ### 流量特征（例如，流量中的模式、异常、协议）
    {traffic_features}

    ### 预匹配的CVE组（来自知识图谱；分析并丰富每个）
    {cve_matches}
    """

    def close(self):
        """Close database connection"""
        self.driver.close()

    def _escape_lucene_special_chars(self, text):
        """Escape special characters in Lucene query syntax"""
        if not text:
            return ""
        special_chars = r'([\+\-&|!(){}[\]^"~*?:\\\/])'
        return re.sub(special_chars, r'\\\1', text)

    def _get_embedding(self, text):
        """Generate text embedding"""
        try:
            vector = self.embeddings.embed_query(text.strip())
            if len(vector) != self.embedding_dimensions:
                logger.warning(
                    f"Embedding dimension mismatch: generated {len(vector)}D, expected {self.embedding_dimensions}D")
                return None
            return vector
        except Exception as e:
            logger.error(f"Failed to generate embedding: {str(e)}")
            return None

    def _parse_date(self, date_str):
        """Parse date string"""
        if not date_str:
            return None
        try:
            return parse(date_str)
        except Exception as e:
            logger.warning(
                f"Failed to parse date string '{date_str}': {str(e)}")
            return None

    def search_cwe(self, attack_description):
        """Search for similar CWEs based on attack description"""
        if not attack_description or not attack_description.strip():
            logger.warning("Empty attack description, CWE search failed")
            return []

        query_embedding = self._get_embedding(attack_description)
        if not query_embedding:
            logger.warning(
                "Failed to generate embedding for attack description, CWE search failed")
            return []

        query = """
        MATCH (c:CWE)
        WHERE c.embedding IS NOT NULL
        WITH c, gds.similarity.cosine(c.embedding, $embedding) AS similarity
        WHERE similarity > $threshold
        ORDER BY similarity DESC
        LIMIT $limit
        RETURN c.id AS cwe_id, c.name AS cwe_name, similarity, c.description AS description
        """

        try:
            with self.driver.session() as session:
                result = session.run(
                    query,
                    embedding=query_embedding,
                    threshold=self.similarity_threshold,
                    limit=self.top_k_cwe
                )
                return [
                    {
                        "cwe_id": record["cwe_id"],
                        "cwe_name": record["cwe_name"],
                        "similarity": float(record["similarity"]),
                        "description": record["description"]
                    }
                    for record in result
                ]
        except Exception as e:
            logger.error(f"CWE search failed: {str(e)}")
            return []

    def _find_cves_by_cwe_ids(self, cwe_ids):
        """Find CVEs related to specific CWEs"""
        if not cwe_ids:
            return []

        query = """
        MATCH (c:CWE)<-[:HAS_WEAKNESS]-(v:CVE)
        WHERE c.id IN $cwe_ids
        WITH DISTINCT v
        ORDER BY v.published_date DESC
        RETURN v.id AS cve_id,
               v.description AS description,
               v.published_date AS published_date,
               v.cvss_v3_score AS cvss_score
        """

        try:
            with self.driver.session() as session:
                result = session.run(query, cwe_ids=cwe_ids)
                cves = []
                for record in result:
                    try:
                        cvss_score = float(
                            record.get("cvss_score", 0.0)) if record.get(
                            "cvss_score") is not None else 0.0
                    except (TypeError, ValueError):
                        cvss_score = 0.0

                    cves.append({
                        "cve_id": record.get("cve_id", ""),
                        "description": record.get("description",
                                                  "No description available"),
                        "published_date": record.get("published_date", ""),
                        "cvss_score": cvss_score,
                        "match_type": "cwe_related"
                    })
                return cves
        except Exception as e:
            logger.error(f"Failed to find CWE-related CVEs: {str(e)}")
            return []

    def search_cve_by_keywords(self, keywords_list):
        """Search CVEs using full-text index for each keyword separately"""
        if not keywords_list:
            return []

        all_results = []
        seen_cves = set()

        for keyword in keywords_list:
            if not keyword or not keyword.strip():
                continue

            escaped_keyword = self._escape_lucene_special_chars(keyword.strip())
            if not escaped_keyword:
                continue

            query = """
            CALL db.index.fulltext.queryNodes("cve_fulltext_index", $keyword) YIELD node, score
            WHERE NOT node.id IN $seen_cves
            RETURN node.id AS cve_id, node.description AS description,
                   node.published_date AS published_date, 
                   COALESCE(node.cvss_v3_score, 0.0) AS cvss_score,
                   score AS keyword_score
            ORDER BY score DESC
            LIMIT $limit
            """

            try:
                with self.driver.session() as session:
                    result = session.run(
                        query,
                        keyword=escaped_keyword,
                        seen_cves=list(seen_cves),
                        limit=self.max_keyword_results_per_term
                    )
                    keyword_results = [
                        {
                            "cve_id": record["cve_id"],
                            "description": record["description"],
                            "published_date": record["published_date"],
                            "cvss_score": float(record["cvss_score"]),
                            "keyword_score": float(record["keyword_score"]),
                            "match_type": "keyword"
                        }
                        for record in result
                    ]

                    all_results.extend(keyword_results)
                    seen_cves.update([r["cve_id"] for r in keyword_results])

            except Exception as e:
                logger.error(
                    f"CVE keyword search failed for keyword '{keyword}': {str(e)}")
                continue

        return all_results

    def search_cve_by_semantics(self, query_text, cve_ids_filter=None):
        """Search CVEs using semantic similarity"""
        if not query_text or not query_text.strip():
            return []

        query_embedding = self._get_embedding(query_text)
        if not query_embedding:
            logger.warning(
                "Failed to generate query embedding, semantic search failed")
            return []

        base_query = """
        MATCH (v:CVE)
        WHERE v.embedding IS NOT NULL
        """
        filter_clause = "AND v.id IN $cve_ids " if cve_ids_filter else ""
        query = f"""
        {base_query}
        {filter_clause}
        WITH v, gds.similarity.cosine(v.embedding, $embedding) AS similarity
        WHERE similarity > $threshold
        RETURN v.id AS cve_id, v.description AS description,
               v.published_date AS published_date, 
               COALESCE(v.cvss_v3_score, 0.0) AS cvss_score,
               similarity AS semantic_score
        ORDER BY similarity DESC
        LIMIT $limit
        """

        params = {
            "embedding": query_embedding,
            "threshold": self.similarity_threshold,
            "limit": self.top_k_cve
        }

        if cve_ids_filter:
            params["cve_ids"] = cve_ids_filter

        try:
            with self.driver.session() as session:
                result = session.run(query, **params)
                return [
                    {
                        "cve_id": record["cve_id"],
                        "description": record["description"],
                        "published_date": record["published_date"],
                        "cvss_score": float(record["cvss_score"]),
                        "semantic_score": float(record["semantic_score"]),
                        "match_type": "semantic"
                    }
                    for record in result
                ]
        except Exception as e:
            logger.error(f"CVE semantic search failed: {str(e)}")
            return []

    def _combine_and_rank_results(self, related_cves, keyword_results,
                                  semantic_results):
        """Combine results with focus on semantic matches only

        Args:
            related_cves: List of CWE-related CVEs (will be ignored)
            keyword_results: List of keyword-matched CVEs (will be ignored)
            semantic_results: List of semantically matched CVEs

        Returns:
            List of top 7 semantic match results with basic info
        """
        # We only care about semantic results, ignore other inputs
        results = []

        # Process semantic results (limited to top 7)
        for cve in semantic_results[:7]:
            try:
                # Extract basic CVE info
                cve_entry = {
                    "cve_id": cve.get("cve_id", ""),
                    "description": cve.get("description",
                                           "No description available"),
                    "published_date": cve.get("published_date", ""),
                    "cvss_score": float(cve.get("cvss_score", 0)) if cve.get(
                        "cvss_score") is not None else 0.0,
                    "match_types": ["semantic"],
                    # Simplified since we only care about semantic matches
                    "match_types_str": "semantic"
                }
                results.append(cve_entry)
            except Exception as e:
                logger.warning(f"Error processing semantic CVE entry: {str(e)}")
                continue

        return results

    def _generate_llm_input(self, product_keywords, traffic_features,
                            cve_results):
        """Prepare LLM input with robust error handling

        Args:
            product_keywords: List of product keywords
            traffic_features: List of traffic features
            cve_results: List of CVE match results

        Returns:
            Dict containing analysis results or error information
        """
        # Initialize default error response
        error_response = {
            "matched_cves": [],
            "attack_type": "",
            "overall_confidence": 0,
            "reason": "生成分析时出错"
        }

        try:
            # Validate input parameters
            if not isinstance(product_keywords, list):
                product_keywords = []
            if not isinstance(traffic_features, list):
                traffic_features = []
            if not isinstance(cve_results, list):
                cve_results = []

            # Prepare CVE matches information
            cve_matches = []
            for i, cve in enumerate(cve_results[:5], 1):  # Limit to top 5
                try:
                    # Safely get description with ellipsis if too long
                    description = cve.get("description", "")
                    if len(description) > 200:
                        description = description[:200].strip() + "..."

                    # Safely format CVE entry
                    cve_entry = (
                        f"{i}. {cve.get('cve_id', 'N/A')} "
                        f"(匹配类型: {cve.get('match_types_str', 'N/A')}, "
                        f"CVSS: {float(cve.get('cvss_score', 0)):.1f})\n"
                        f"发布日期: {cve.get('published_date', '未知')}\n"
                        f"描述: {description}"
                    )
                    cve_matches.append(cve_entry)
                except Exception as e:
                    logger.warning(f"Error formatting CVE entry: {str(e)}")
                    continue

            # Safely format user prompt
            try:
                user_prompt = self.user_prompt_template.format(
                    product_keywords=", ".join(
                        str(kw) for kw in product_keywords),
                    traffic_features="\n".join(
                        str(tf) for tf in traffic_features),
                    cve_matches="\n\n".join(
                        cve_matches) if cve_matches else "无匹配CVE"
                )
            except Exception as e:
                logger.error(f"Prompt formatting error: {str(e)}")
                error_response["reason"] = "提示词格式化错误"
                return error_response

            # Get LLM response with timeout protection
            try:
                llm_response = self.analyzer.analyze(
                    system_prompt=self.system_prompt,
                    user_prompt=user_prompt
                )

                # Handle empty response
                if not llm_response:
                    error_response["reason"] = "LLM返回空响应"
                    return error_response

                # Parse JSON response
                if isinstance(llm_response, str):
                    try:
                        parsed = json.loads(llm_response)
                        if not isinstance(parsed, dict):
                            raise ValueError(
                                "LLM response is not a JSON object")
                        return parsed
                    except (json.JSONDecodeError, ValueError) as e:
                        logger.error(f"LLM response parsing failed: {str(e)}")
                        error_response["reason"] = "LLM返回格式无效"
                        return error_response

                elif isinstance(llm_response, dict):
                    return llm_response
                else:
                    error_response["reason"] = "LLM返回无效类型"
                    return error_response

            except Exception as e:
                logger.error(f"LLM analysis failed: {str(e)}")
                error_response["reason"] = f"LLM分析失败: {str(e)}"
                return error_response

        except Exception as e:
            logger.error(f"Unexpected error in LLM input generation: {str(e)}")
            error_response["reason"] = f"意外错误: {str(e)}"
            return error_response

    def _extract_file_number(self, file_stem: str) -> str:
        """Extract number from filename"""
        parts = file_stem.split('_')
        return parts[-1] if len(parts) > 1 else "0"

    def _safe_json_load(self, json_str):
        """Safely load JSON data that might be NaN or other non-string values"""
        if pd.isna(json_str) or json_str is None:
            return []
        try:
            if isinstance(json_str, (int, float)):
                return []
            return json.loads(json_str) if isinstance(json_str, str) else []
        except json.JSONDecodeError:
            return []

    def analyze(self, input_dir: str, output_dir: str):
        """
        Process all CSVs in input_dir and output to output_dir with matching filenames
        Modified to make keyword search global (not limited to CWE-related CVEs)
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        input_files = sorted(glob.glob(os.path.join(input_dir, '*.csv')))

        #for input_file in tqdm(input_files, desc="CVE 漏洞分析"):
        for input_file in input_files:
            try:
                file_name = os.path.basename(input_file)
                file_stem = Path(input_file).stem
                file_num = self._extract_file_number(file_stem)
                output_file = os.path.join(output_dir,
                                           f"cve_analysis_{file_num}.csv")

                # Read CSV with proper handling of NaN values
                df = pd.read_csv(input_file, keep_default_na=False)
                results = []

                for _, row in df.iterrows():
                    row_data = row.to_dict()  # Preserve all original columns

                    # Extract analysis fields
                    traffic_features = [
                        str(row.get(f"{self.analysis_prefix}search_description",
                                    "")),
                        str(row.get(
                            f"{self.analysis_prefix}rsearch_description", ""))
                    ]
                    cwe_keywords = str(
                        row.get(f"{self.analysis_prefix}cwe_keywords", ""))

                    product_keywords = self._safe_json_load(
                        row.get(f"{self.analysis_prefix}special_product", "[]")
                    )

                    cve_keywords = str(
                        row.get(f"{self.analysis_prefix}cve_keywords", ""))

                    if not cve_keywords:
                        row_data[f"{self.analysis_prefix}error"] = "缺少CVE关键词"
                        results.append(row_data)
                        continue

                    # 1. Perform CWE search first
                    cwe_results = self.search_cwe(
                        "\n".join([cwe_keywords] + traffic_features))
                    related_cves = self._find_cves_by_cwe_ids(
                        [item["cwe_id"] for item in cwe_results])

                    # Initialize result containers
                    keyword_results = []
                    semantic_results = []

                    # 2. Always perform global keyword search (modified part)
                    if product_keywords:
                        keyword_results = self.search_cve_by_keywords(
                            product_keywords)
                        # Remove the filtering of CWE-related CVEs here to make it global

                    # 3. Semantic search with scope control
                    if related_cves:  # If we have CWE-related CVEs
                        # Phase 1: First try semantic search in keyword results (if any)
                        if keyword_results:
                            search_scope = [cve["cve_id"] for cve in
                                            keyword_results]
                            semantic_results = self.search_cve_by_semantics(
                                cve_keywords, search_scope)

                        # Phase 2: If no results, try in CWE-related CVEs
                        if not semantic_results:
                            search_scope = [cve["cve_id"] for cve in
                                            related_cves]
                            semantic_results = self.search_cve_by_semantics(
                                cve_keywords, search_scope)
                    else:  # No CWE matches
                        # Phase 1: Try semantic search in keyword results (if any)
                        if keyword_results:
                            search_scope = [cve["cve_id"] for cve in
                                            keyword_results]
                            semantic_results = self.search_cve_by_semantics(
                                cve_keywords, search_scope)

                        # Phase 2: Global semantic search if no keyword results or no matches
                        if not semantic_results:
                            semantic_results = self.search_cve_by_semantics(
                                cve_keywords)

                    # Combine results (only semantic results considered)
                    combined_results = self._combine_and_rank_results(
                        related_cves,
                        keyword_results,
                        semantic_results
                    )

                    if not combined_results:
                        row_data[f"{self.analysis_prefix}error"] = "无匹配结果"
                        results.append(row_data)
                        continue

                    # Call LLM analysis
                    llm_input = self._generate_llm_input(
                        product_keywords,
                        traffic_features,
                        combined_results[:5]  # Top 5 results for analysis
                    )
                    llm_result = llm_input

                    # Update results
                    matched_cves = llm_result.get("matched_cves", [])
                    if not isinstance(matched_cves, list):
                        matched_cves = []

                    row_data.update({
                        f"{self.analysis_prefix}matched_cves": "; ".join(
                            str(cve.get("id", "")) for cve in matched_cves),
                        f"{self.analysis_prefix}top_cve": (
                            str(matched_cves[0]["id"])
                            if matched_cves and isinstance(matched_cves[0],
                                                           dict)
                            else "无"),
                        f"{self.analysis_prefix}attack_type": str(
                            llm_result.get("attack_type", "")),
                        f"{self.analysis_prefix}threat_confidence": float(
                            llm_result.get("overall_confidence", 0)),
                        f"{self.analysis_prefix}reason": str(
                            llm_result.get("reason", ""))
                    })
                    results.append(row_data)

                # Write CSV
                pd.DataFrame(results).to_csv(output_file, index=False,
                                             encoding='utf-8-sig')
                print(f"✅ 处理完成: {file_name} -> {os.path.basename(output_file)}")

            except Exception as e:
                logger.error(f"❌ Error processing file {file_name}: {e}")
                continue