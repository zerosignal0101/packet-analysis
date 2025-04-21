# 请求路径分类函数
def classify_path(path):
    if 'post' in path.lower() or path == '/portal_todo_moa/api/getDataByUserId':
        return 'api_post'
    elif 'get' in path.lower():
        return 'api_get'
    elif '/static/' in path or path.endswith(('.css', '.js', '.png', '.jpg', '.gif')):
        return 'static_resource'
    elif path.endswith(('.php', '.asp', '.jsp', '.html')):
        return 'dynamic_resource'
    else:
        return 'other'
