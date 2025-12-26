# ----------------- deepseek_analyzer.py -----------------
import json
import requests
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type
)
from config import Config


class DeepSeekAnalyzer:
    def __init__(self):
        self.api_url = Config.DEEPSEEK_API_URL
        self.api_key = Config.DEEPSEEK_API_KEY
        self.cache_key = None  # 用于存储缓存键

    @retry(
        stop=stop_after_attempt(Config.DEEPSEEK_MAX_RETRIES),
        wait=wait_exponential(multiplier=1, min=3, max=30),
        retry=retry_if_exception_type(requests.exceptions.RequestException)
    )
    def analyze(self, user_prompt, system_prompt=None, context=None, **kwargs):
        """
        通用分析接口
        :param user_prompt: 用户提示词 (必须)
        :param system_prompt: 系统角色设定 (可选)
        :param context: 上下文数据 (可选)
        :param kwargs: 其他API参数 (如temperature, max_tokens等)
        :return: 解析后的JSON结果或错误信息
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "X-DEEPSEEK-CACHE-KEY": str(
                self.cache_key) if self.cache_key else ""
        }

        # 构建消息链
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})

        if context is not None:
            messages[-1]["content"] += "\n上下文数据：" + json.dumps(context)

        # 基础参数 + 用户自定义参数
        base_payload = {
            "model": "deepseek-chat",
            "messages": messages,
            "temperature": 0.3,  # 默认值
            "max_tokens": 3000,  # 默认值
            "response_format": {"type": "json_object"},
            "use_cache": True
        }
        payload = {**base_payload, **kwargs}  # 合并参数

        try:
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=Config.DEEPSEEK_API_TIMEOUT
            )
            response.raise_for_status()

            # 更新缓存键
            self.cache_key = response.headers.get("X-DEEPSEEK-CACHE-KEY")

            # 统一解析逻辑
            result = response.json()
            content = result.get("choices", [{}])[0].get("message", {}).get(
                "content", "{}")

            if isinstance(content, str):
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    return {"error": "Invalid JSON response",
                            "content": content}
            return content

        except Exception as e:
            return {
                "error": f"API request failed: {str(e)}",
                "exception_type": type(e).__name__
            }