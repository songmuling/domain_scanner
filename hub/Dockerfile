FROM python:3.12-alpine

WORKDIR /app

ENV PYTHONUNBUFFERED=1

# 复制脚本与静态前端 (作为独立镜像基础；Compose 模式下由 volumes 动态映射覆盖，git pull 后无需 rebuild)
COPY server.py /app/server.py
COPY static /app/static

EXPOSE 8088

CMD ["python", "server.py", "8088"]

