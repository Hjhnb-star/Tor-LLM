# ----------------- main.py -----------------
import os
import glob
import logging
import pandas as pd
from pathlib import Path
from typing import Callable
from tqdm import tqdm

from process import PcapProcessor
from feature_analysis import EnhancedFeatureAnalyzer
from feature_consolidator import FeatureConsolidator
from cve_evaluator import Neo4jCVEAnalyzer
from integrate_analysis import IntegrationAnalyzer
from request_response_analysis import ContentAnalyzer

# ================= 配置区域 =================
PCAP_DIR = r"E:\test"  # ✅ 填你的PCAP目录
# 若已有CSV，可设为 None，直接改走 CSV 模式
# ===========================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('analysis.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / 'results'


# ---------- 通用目录处理工具 ----------
def process_directory(
        input_dir: Path,
        output_dir: Path,
        process_fn: Callable[[pd.DataFrame], pd.DataFrame],
        out_prefix: str,
        file_pattern: str = '*.csv'
):
    """处理目录中的所有匹配文件"""
    output_dir.mkdir(parents=True, exist_ok=True)
    in_files = sorted(glob.glob(str(input_dir / file_pattern)))

    for in_path in tqdm(in_files, desc=f"处理 {out_prefix}"):
        try:
            idx = Path(in_path).stem.rsplit('_', 1)[-1]
            out_path = output_dir / f'{out_prefix}_{idx}.csv'

            # 读取文件
            df = pd.read_csv(in_path)

            # 处理数据
            processed_df = process_fn(df)

            # 保存结果
            processed_df.to_csv(out_path, index=False, encoding='utf-8-sig')
            logging.info(f'✅ {Path(in_path).name} -> {out_path.name}')
        except Exception as e:
            logging.error(f'❌ 处理文件 {in_path} 失败: {e}')
            continue


# ---------- 1. PCAP → CSV ----------
def run_pcap_pipeline():
    """处理PCAP文件生成CSV"""
    pcap_out = RESULTS_DIR / 'pcap_outputs'
    pcap_out.mkdir(parents=True, exist_ok=True)
    processor = PcapProcessor()
    ok = processor.process_pcap_files(PCAP_DIR,
                                      str(pcap_out / 'test_pcap_features'),
                                      max_workers=8)
    if not ok:
        raise RuntimeError("PCAP处理失败")
    return pcap_out


# ---------- 2. 后续分析流水线 ----------
def run_analysis_pipeline(input_dir: Path):
    """执行分析流水线"""

    # 2.1 特征增强
    feature_out = RESULTS_DIR / 'feature_outputs'
    EnhancedFeatureAnalyzer().analyze(str(input_dir), str(feature_out))

    # 2.4 内容分析
    content_out = RESULTS_DIR / 'content_outputs'
    ContentAnalyzer().analyze(str(feature_out), str(content_out))

    # 2.5 关键词整合
    keyword_out = RESULTS_DIR / 'keyword_outputs'
    FeatureConsolidator().consolidate(str(content_out), str(keyword_out))

    # 2.6 CVE 关联
    cve_out = RESULTS_DIR / 'cve_outputs'
    Neo4jCVEAnalyzer().analyze(str(keyword_out), str(cve_out))

    # 2.7 最终报告
    final_out = RESULTS_DIR / 'final_outputs'
    IntegrationAnalyzer().analyze(str(cve_out), str(final_out))




def main():
    """主函数"""
    if not PCAP_DIR or not os.path.isdir(PCAP_DIR):
        logging.error("❌ 请配置正确的 PCAP_DIR")
        return

    try:
        #logging.info("🚀 开始处理PCAP文件...")
        print("🚀 开始处理PCAP文件...")
        pcap_dir = run_pcap_pipeline()

        #logging.info("🔍 开始特征分析...")
        print("🔍 开始特征分析...")
        run_analysis_pipeline(pcap_dir)

        #logging.info("🎉 全流程完成！结果保存在 %s", RESULTS_DIR)
        print("🎉 全流程完成！结果保存在", RESULTS_DIR)
    except Exception as e:
        logging.exception("❌ 程序异常终止: %s", e)


if __name__ == '__main__':
    main()