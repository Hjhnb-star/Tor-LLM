# ----------------- config.py -----------------
import os


class Config:
    # 原始输入列（保持不变）
    CSV_COLUMNS = [
        'src_ip','dst_ip','src_port','dst_port','u_avg_http_size','u_var_http_size','d_avg_http_size','d_var_http_size','u_avg_interval','u_var_interval','d_avg_interval','d_var_interval','stream_duration','request_count','response_count','status_codes','full_request','full_response','source_pcap'
    ]

    # 新增配置（控制列保留策略）
    PRESERVE_ALL_COLUMNS = True  # 强制保留所有原始列
    ANALYSIS_COL_PREFIX = "analysis_"  # 新增分析列的统一前缀



    DEEPSEEK_API_KEY = ""
    DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
    DEEPSEEK_API_TIMEOUT = 60
    DEEPSEEK_MAX_RETRIES = 5

    HTTP_PORTS=[80, 443, 8080, 8088, 8000, 8008, 8888, 8443]
    CLIENT_IP=""

    # Neo4j配置
    NEO4J_URI = r'bolt://localhost:7687'
    NEO4J_USER = 'neo4j'
    NEO4J_PASSWORD = ''
    NEO4J_IMPORT_DIR = r""
    EMBEDDING_DIMENSIONS = 2560  # 与您的embedding维度一致
    EMBEDDING_MODEL = "dengcao/Qwen3-Embedding-4B:Q4_K_M"

    VIRUSTOTAL_API_KEY = 'your key'
    FOFA_API_KEY = 'your key'
    FOFA_EMAIL = 'your email'
class DataProcessor:
    @staticmethod
    def save_output(df, output_path, module_name=None):
        """智能保存方法（自动处理列名）"""
        try:
            # 规范化路径
            output_path = os.path.abspath(output_path)

            # 确保目录存在
            os.makedirs(os.path.dirname(output_path), exist_ok=True)

            # 保存数据
            df.to_excel(output_path, index=False)
            print(f"✅ 结果保存至：{output_path}")
            return True
        except Exception as e:
            print(f"❌ 保存失败：{str(e)}")
            return False
