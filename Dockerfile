# 使用官方的Python 3.10镜像作为基础镜像
FROM python:3.10-slim-bullseye

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
    zlib1g-dev 

# 安装PDM和tshark所需的依赖
RUN apt-get update 
RUN apt-get install -y --no-install-recommends \
    curl 
RUN apt-get install -y --no-install-recommends \
    libpcap-dev \
    tshark
RUN apt-get clean 
RUN rm -rf /var/lib/apt/lists/*

# 安装PDM
RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/
RUN pip install pdm
RUN pdm config pypi.url https://mirrors.aliyun.com/pypi/simple/

# 复制项目文件到工作目录
COPY . /app

# 使用PDM安装项目依赖
RUN pdm install

# 暴露端口7956
EXPOSE 7956

# 启动应用
CMD ["pdm", "run", "webui.py"]