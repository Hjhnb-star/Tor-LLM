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
        self.max_keyword_results_per_term = 3  # Max CVEs to return per keyword
        self.system_prompt = """
        您是一位网络安全威胁分析专家，专注于使用CVE漏洞评估网络流量中的潜在恶意攻击。您的任务是基于提供的设备组件关键词、流量特征和预匹配的CVE组来评估威胁。利用您的工具进行实时搜索以增强分析。

分析要求：
1. 首先，使用您的网络搜索工具独立发现可能的CVE：
   - 搜索与产品关键词（例如，IoT设备、组件或型号）和流量特征相关的漏洞。
   - 查询示例：'CVE vulnerabilities in [product_keywords] involving [traffic_features]' 或 site:nvd.nist.gov 以获取特定匹配。
   - 为任何找到的CVE检索详细描述、受影响的产品、利用细节和发布日期。
   - 最初目标是找到3-5个相关CVE以进行比较。

2. 接下来，对于提供的cve_matches（来自知识图谱筛选的分组CVE）：
   - 使用工具为每个CVE ID获取额外细节，例如浏览 https://nvd.nist.gov/vuln/detail/[CVE-ID] 或搜索扩展描述、exploit-db条目或相关公告。
   - 用影响、CVSS分数、受影响版本和真实世界利用示例进行丰富（如果可用）。

3. 比较两组CVE（您搜索到的与提供的cve_matches）：
   - 语义上评估每个CVE/组与流量特征和产品关键词的匹配质量。
   - 优先考虑：
      - 与产品关键词的高匹配度（例如，确切的设备/型号提及）。
      - 与CVE关键词/描述的高语义相似度与流量特征（例如，如果流量显示溢出模式，则缓冲区溢出）。
      - 更近的发布日期（优先考虑更新的CVE以相关当前威胁）。
   - 如果您搜索到的CVE更好地匹配流量特征，则优先选择它们；否则，优化或与提供的结合。

4. 全面评估整体威胁：
   - 从组合结果中选择1-2个最匹配的CVE。
   - 确定可能的攻击类型（例如，缓冲区溢出、远程代码执行）。
   - 根据证据分配置信度分数（0.0 到 1.0）。

5. 严格以JSON格式返回，无额外文本：
{{
  "matched_cves": [
    {{
      "id": "CVE-ID",
      "confidence": 0.0,
      "match_reason": "详细原因，包括产品/CVE关键词匹配、流量特征对齐，以及任何工具来源的证据"
    }}
  ],
  "attack_type": "推断的攻击类型，例如 'Remote Code Execution via Buffer Overflow'",
  "overall_confidence": 0.0,
  "reason": "选择、搜索与提供CVE之间比较的全面推理，以及为什么这些是最佳匹配"
}}
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

    def interactive_test(self):
        """交互式测试界面"""
        print("\n" + "=" * 50)
        print("CVE分析器交互式测试模式")
        print("=" * 50)

        while True:
            print("\n请选择要测试的功能:")
            print("1. CWE搜索")
            print("2. 关键词搜索")
            print("3. 语义搜索")
            print("4. 完整组合搜索")
            print("5. 退出测试")

            choice = input("请输入选项(1-5): ").strip()

            if choice == "5":
                print("\n退出测试模式")
                break

            if choice not in ["1", "2", "3", "4"]:
                print("无效输入，请重新选择")
                continue

            # 获取查询输入
            if choice in ["1", "4"]:
                attack_desc = input(
                    "请输入攻击描述(例如:Apache HTTP漏洞): ").strip()

            if choice in ["2", "4"]:
                keywords = input("请输入产品关键词(多个词用逗号分隔): ").strip()
                keyword_list = [k.strip() for k in keywords.split(",") if
                                k.strip()]

            if choice in ["3", "4"]:
                semantic_query = input(
                    "请输入语义查询(例如:缓冲区溢出漏洞): ").strip()

            print("\n" + "-" * 50)
            print("测试结果:")

            try:
                if choice == "1":
                    # 测试CWE搜索
                    results = self.search_cwe(attack_desc)
                    self._display_results("CWE搜索", [{
                        "id": r["cwe_id"],
                        "description": r["description"],
                        "similarity": r["similarity"]
                    } for r in results])

                elif choice == "2":
                    # 测试关键词搜索
                    results = self.search_cve_by_keywords(keyword_list)
                    self._display_results("关键词搜索", results)

                elif choice == "3":
                    # 测试语义搜索
                    results = self.search_cve_by_semantics(semantic_query)
                    self._display_results("语义搜索", results)

                elif choice == "4":
                    # 测试完整组合搜索
                    print("执行完整搜索流程...")

                    # 1. CWE搜索
                    cwe_results = self.search_cwe(attack_desc)
                    print(f"找到 {len(cwe_results)} 个相关CWE")

                    # 2. 获取相关CVE
                    cwe_ids = [r["cwe_id"] for r in cwe_results]
                    related_cves = self._find_cves_by_cwe_ids(cwe_ids)
                    print(f"找到 {len(related_cves)} 个CWE相关CVE")

                    # 3. 关键词搜索
                    keyword_results = self.search_cve_by_keywords(keyword_list)
                    print(f"找到 {len(keyword_results)} 个关键词匹配CVE")

                    # 4. 语义搜索
                    semantic_results = self.search_cve_by_semantics(
                        semantic_query)
                    print(f"找到 {len(semantic_results)} 个语义匹配CVE")

                    # 5. 组合结果
                    combined = self._combine_and_rank_results(
                        related_cves,
                        keyword_results,
                        semantic_results
                    )

                    self._display_results("组合搜索结果", combined)

            except Exception as e:
                print(f"测试失败: {str(e)}")

            input("\n按Enter键继续...")

    def _display_results(self, title, results):
        """显示搜索结果"""
        print(f"\n{title}结果 (共 {len(results)} 条):")
        if not results:
            print("无结果")
            return

        for i, item in enumerate(results[:5], 1):  # 最多显示5条
            print(f"\n{i}. {item.get('cve_id', item.get('id', 'N/A'))}")

            # 处理不同类型的结果格式
            if 'match_types_str' in item:
                print(f"类型: {item['match_types_str']}")
            elif 'match_type' in item:
                print(f"类型: {item['match_type']}")
            else:
                print("类型: N/A")

            # 处理不同分数字段
            score = item.get('final_score',
                             item.get('semantic_score',
                                      item.get('keyword_score',
                                               item.get('similarity', 0))))
            print(f"分数: {score:.2f}")

            print(f"CVSS: {item.get('cvss_score', 0):.1f}")
            print(f"描述: {item.get('description', '无描述')[:100]}...")
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
        """Combine and rank results from different search methods"""
        result_dict = {}

        # Add related CVEs
        for cve in related_cves:
            cve_id = cve["cve_id"]
            result_dict[cve_id] = {
                "cve_id": cve_id,
                "description": cve["description"],
                "published_date": cve["published_date"],
                "cvss_score": cve["cvss_score"],
                "match_types": [cve["match_type"]],
                "keyword_score": 0,
                "semantic_score": 0,
                "final_score": 0  # Will be updated based on actual matches
            }

        # Add keyword search results
        for cve in keyword_results:
            cve_id = cve["cve_id"]
            if cve_id in result_dict:
                result_dict[cve_id]["keyword_score"] = cve["keyword_score"]
                result_dict[cve_id]["match_types"].append(cve["match_type"])
            else:
                result_dict[cve_id] = {
                    "cve_id": cve_id,
                    "description": cve["description"],
                    "published_date": cve["published_date"],
                    "cvss_score": cve["cvss_score"],
                    "match_types": [cve["match_type"]],
                    "keyword_score": cve["keyword_score"],
                    "semantic_score": 0,
                    "final_score": 0
                }

        # Add semantic search results
        for cve in semantic_results:
            cve_id = cve["cve_id"]
            if cve_id in result_dict:
                result_dict[cve_id]["semantic_score"] = cve["semantic_score"]
                result_dict[cve_id]["match_types"].append(cve["match_type"])
            else:
                result_dict[cve_id] = {
                    "cve_id": cve_id,
                    "description": cve["description"],
                    "published_date": cve["published_date"],
                    "cvss_score": cve["cvss_score"],
                    "match_types": [cve["match_type"]],
                    "keyword_score": 0,
                    "semantic_score": cve["semantic_score"],
                    "final_score": 0
                }

        # Calculate final scores (no weighting, just use the highest available score)
        for cve_id in result_dict:
            scores = []
            if result_dict[cve_id]["keyword_score"] > 0:
                scores.append(result_dict[cve_id]["keyword_score"])
            if result_dict[cve_id]["semantic_score"] > 0:
                scores.append(result_dict[cve_id]["semantic_score"])

            # If we have both scores, use the higher one
            if scores:
                result_dict[cve_id]["final_score"] = max(scores)
            else:
                # For CWE-related CVEs with no other matches, give a small score
                result_dict[cve_id]["final_score"] = 0.1 if "cwe_related" in \
                                                            result_dict[cve_id][
                                                                "match_types"] else 0

        # Convert to list and sort
        results = list(result_dict.values())
        results.sort(
            key=lambda x: (
                -x["final_score"],
                -x["cvss_score"],
                -self._parse_date(x["published_date"]).timestamp() if x[
                    "published_date"] else 0
            )
        )

        # Format match types
        for result in results:
            result["match_types"] = list(set(result["match_types"]))
            result["match_types_str"] = ", ".join(result["match_types"])

        return results

    def _generate_llm_input(self, product_keywords, traffic_features,
                            cve_results):
        """Prepare LLM input"""
        cve_matches = []

        for i, cve in enumerate(cve_results, 1):
            desc = cve["description"][:150] + "..." if len(
                cve["description"]) > 150 else cve["description"]

            cve_matches.append(
                f"{i}. {cve['cve_id']} (匹配类型: {cve['match_types_str']}, "
                f"分数: {cve['final_score']:.2f}, CVSS: {cve['cvss_score']:.1f})\n"
                f"发布日期: {cve['published_date']}\n"
                f"描述: {desc}"
            )

        return (self.analyzer.analyze(system_prompt=self.system_prompt,
                                      user_prompt=self.user_prompt_template.format(
                                          product_keywords=", ".join(
                                              product_keywords),
                                          traffic_features="\n".join(
                                              traffic_features),
                                          cve_matches="\n\n".join(
                                              cve_matches))))

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

        Args:
            input_dir: Directory containing input CSV files
            output_dir: Directory to save output CSV files
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # List and sort all CSV files
        input_files = sorted(glob.glob(os.path.join(input_dir, '*.csv')))

        for input_file in tqdm(input_files, desc="CVE 漏洞分析"):
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

                    # Safely handle product_keywords which might be NaN/float
                    product_keywords = self._safe_json_load(
                        row.get(f"{self.analysis_prefix}special_product", "[]")
                    )

                    cve_keywords = str(
                        row.get(f"{self.analysis_prefix}cve_keywords", ""))

                    if not cve_keywords:
                        row_data[f"{self.analysis_prefix}error"] = "缺少CVE关键词"
                        results.append(row_data)
                        continue

                    # Perform CWE search first
                    cwe_results = self.search_cwe(
                        "\n".join([cwe_keywords] + traffic_features))
                    related_cves = self._find_cves_by_cwe_ids(
                        [item["cwe_id"] for item in cwe_results])

                    # Determine search scope based on CWE results
                    search_scope = [cve["cve_id"] for cve in
                                    related_cves] if related_cves else None

                    # Phase 1: Keyword search (for each product keyword separately)
                    keyword_results = []
                    if product_keywords:
                        keyword_results = self.search_cve_by_keywords(
                            product_keywords)
                        if search_scope:  # Filter to CWE-related CVEs if available
                            keyword_results = [cve for cve in keyword_results if
                                               cve["cve_id"] in search_scope]

                    # If we have keyword results, use them for semantic search scope
                    semantic_search_scope = [cve["cve_id"] for cve in
                                             keyword_results] if keyword_results else search_scope

                    # Phase 2: Semantic search
                    semantic_results = self.search_cve_by_semantics(
                        cve_keywords,
                        semantic_search_scope if semantic_search_scope else None
                    )

                    # If no results from semantic search in limited scope, try global search
                    if not semantic_results and not semantic_search_scope:
                        semantic_results = self.search_cve_by_semantics(
                            cve_keywords)

                    # Combine results
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
                    llm_result = self.analyzer.analyze(llm_input, {})

                    # Update results
                    matched_cves = llm_result.get("matched_cves", [])
                    row_data.update({
                        f"{self.analysis_prefix}matched_cves": "; ".join(
                            f"{cve['id']}" for cve in matched_cves),
                        f"{self.analysis_prefix}top_cve": matched_cves[0][
                            "id"] if matched_cves else "无",
                        f"{self.analysis_prefix}attack_type": llm_result.get(
                            "attack_type", ""),
                        f"{self.analysis_prefix}threat_confidence": llm_result.get(
                            "overall_confidence", 0),
                        f"{self.analysis_prefix}reason": llm_result.get(
                            "reason", "")
                    })
                    results.append(row_data)

                # Write CSV
                pd.DataFrame(results).to_csv(output_file, index=False,
                                             encoding='utf-8-sig')
                logger.info(
                    f"✅ CVE analysis completed: {file_name} -> {os.path.basename(output_file)}")

            except Exception as e:
                logger.error(f"❌ Error processing file {file_name}: {e}")
                continue


if __name__ == "__main__":
    # 配置您的Neo4j连接信息
    NEO4J_URI = "bolt://localhost:7687"
    NEO4J_USER = "neo4j"
    NEO4J_PASSWORD = "hjh737505"

    analyzer = None
    try:
        analyzer = Neo4jCVEAnalyzer()
        analyzer.interactive_test()
    except Exception as e:
        print(f"初始化失败: {str(e)}")
    finally:
        if analyzer:
            analyzer.close()