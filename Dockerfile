# 第一阶段：构建依赖
FROM python:3.11-slim-bullseye as builder

# 设置非交互式环境变量
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# 设置工作目录
WORKDIR /packet-analysis

# 换源
RUN mv /etc/apt/sources.list /etc/apt/sources.list.bak
RUN echo "deb http://mirrors.ustc.edu.cn/debian/ bullseye main contrib non-free" > /etc/apt/sources.list && \
    echo "deb-src http://mirrors.ustc.edu.cn/debian/ bullseye main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.ustc.edu.cn/debian/ bullseye-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb-src http://mirrors.ustc.edu.cn/debian/ bullseye-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.ustc.edu.cn/debian/ bullseye-backports main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb-src http://mirrors.ustc.edu.cn/debian/ bullseye-backports main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.ustc.edu.cn/debian-security bullseye-security main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb-src http://mirrors.ustc.edu.cn/debian-security bullseye-security main contrib non-free" >> /etc/apt/sources.list

# 安装必要的系统依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    curl \
    libpcap-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 安装PDM
RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/ \
    && pip install pdm \
    && pdm config pypi.url https://mirrors.aliyun.com/pypi/simple/

# 复制项目文件到工作目录
COPY ./pyproject.toml /packet-analysis
COPY ./pdm.lock /packet-analysis

# 使用PDM安装项目依赖
RUN pdm install

# 第二阶段：运行环境
FROM python:3.10-slim-bullseye

# 设置工作目录
WORKDIR /packet-analysis

# 设置非交互式环境变量
ENV DEBIAN_FRONTEND=noninteractive

# 换源
RUN mv /etc/apt/sources.list /etc/apt/sources.list.bak
RUN echo "deb http://mirrors.ustc.edu.cn/debian/ bullseye main contrib non-free" > /etc/apt/sources.list && \
    echo "deb-src http://mirrors.ustc.edu.cn/debian/ bullseye main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.ustc.edu.cn/debian/ bullseye-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb-src http://mirrors.ustc.edu.cn/debian/ bullseye-updates main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.ustc.edu.cn/debian/ bullseye-backports main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb-src http://mirrors.ustc.edu.cn/debian/ bullseye-backports main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.ustc.edu.cn/debian-security bullseye-security main contrib non-free" >> /etc/apt/sources.list && \
    echo "deb-src http://mirrors.ustc.edu.cn/debian-security bullseye-security main contrib non-free" >> /etc/apt/sources.list

# 安装必要的Tshark
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    tshark \
    libpcap-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 从构建阶段复制虚拟环境
COPY --from=builder /packet-analysis/.venv /packet-analysis/.venv

## 复制项目文件
#COPY ./packet_analysis /packet-analysis/packet_analysis
#COPY ./run.py /packet-analysis
#COPY ./server.py /packet-analysis

# 设置挂载目录
VOLUME /packet-analysis/raw_data
VOLUME /packet-analysis/results
VOLUME /packet-analysis/src

# 设置环境变量
ENV PATH="/packet-analysis/.venv/bin:$PATH"
ENV PYTHONPATH=/packet-analysis
ENV CELERY_BROKER_URL=redis://redis:6379/0
ENV CELERY_RESULT_BACKEND=redis://redis:6379/1
ENV ENABLE_CELERY_BEAT=true
ENV CELERY_BEAT_DIR=/packet-analysis/celerybeat
# Openblas multi thread restriction
ENV OPENBLAS_NUM_THREADS=4

# 暴露端口7956
EXPOSE 7956

# Default command (can be overridden) - useful for basic checks
CMD ["python", "--version"]
