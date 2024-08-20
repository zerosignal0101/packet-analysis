# 第一阶段：构建依赖
FROM python:3.10-slim-bullseye as builder

# 设置非交互式环境变量
ENV DEBIAN_FRONTEND=noninteractive

# 设置工作目录
WORKDIR /app

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
COPY ./pyproject.toml /app
COPY ./pdm.lock /app

# 使用PDM安装项目依赖
RUN pdm install

# 第二阶段：运行环境
FROM python:3.10-slim-bullseye

# 设置工作目录
WORKDIR /app

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
COPY --from=builder /app/.venv /app/.venv

# 复制项目文件
COPY ./packet_analysis /app/packet_analysis
COPY ./run.py /app
COPY ./server.py /app

# 设置挂载目录
VOLUME /app/raw_data
VOLUME /app/results

# 设置环境变量
ENV PATH="/app/.venv/bin:$PATH"

# 暴露端口7956
EXPOSE 7956

# 启动应用
CMD ["python", "server.py"]
