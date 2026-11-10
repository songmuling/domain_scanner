FROM python:3.12-alpine

WORKDIR /app

# 复制核心扫描器与 Agent 守护脚本
COPY domain_scanner.py /app/
COPY agent.py /app/

CMD ["python", "agent.py"]

