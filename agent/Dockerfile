FROM python:3.12-alpine

WORKDIR /app

ENV PYTHONUNBUFFERED=1

# 复制核心扫描器与 Agent 守护脚本 (作为独立镜像基础；Compose 模式下由 volumes 动态映射覆盖)
COPY scanner.py /app/
COPY agent.py /app/

CMD ["python", "agent.py"]

