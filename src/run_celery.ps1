# 检查conda是否在PATH中，如果不在，可能需要手动添加conda的路径
if (-Not (Get-Command conda -ErrorAction SilentlyContinue)) {
    Write-Error "Conda does not seem to be in PATH. Please ensure Anaconda/Miniconda is installed and added to PATH."
    exit 1
}

# # 初始化Conda for PowerShell，如果你是第一次在PowerShell中使用Conda
# conda init powershell
#
# # 重新加载当前会话以应用初始化（仅首次初始化时需要）
# $env:CONDA_SHLVL = 0
# & $env:CONDA_EXE "shell.powershell" "hook" | Out-String | Invoke-Expression

# 激活wireshark环境
conda activate wireshark

# 检查是否成功激活环境（可选）
Write-Host "当前激活的环境：$(conda info --envs | sls '^\* +' | % { $_.ToString().Trim('* ') })"

# # 指定Redis服务器可执行文件的路径
# $redisExecutablePath = "C:\Program Files\Redis\redis-server.exe"
# if (Test-Path $redisExecutablePath) {
#     # 使用Start-Process在后台启动Redis
#     Start-Process -FilePath $redisExecutablePath -NoNewWindow -RedirectStandardOutput "redis_output.log" -RedirectStandardError "redis_error.log"
#     Write-Host "Redis has been started in the background. Check redis_output.log and redis_error.log for output."
# } else {
#     Write-Warning "Redis executable not found at the specified path: $($redisExecutablePath)"
# }

# 运行Celery命令
celery -A src.server.celery worker --loglevel=info -P eventlet

# 注意：上述脚本假设你已经配置好了环境和所有必要的依赖。
