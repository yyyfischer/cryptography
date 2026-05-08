import hashlib

def compute_hash_chain(file_path):
    # 1. 以二进制方式打开文件，读取视频内容
    with open(file_path, "rb") as f:
        data = f.read()

    # 2. 按照 1KB（1024字节）将文件分成一块一块
    block_size = 1024
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]

    # 3. 反转分块顺序：从最后一块开始往前计算（哈希链规则）
    blocks.reverse()

    # 4. 开始计算哈希链
    current_hash = b""  # 初始哈希为空
    for block in blocks:
        combined = block + current_hash       # 把当前块 + 上一个哈希拼在一起
        h = hashlib.sha256(combined)          # 计算 SHA256 哈希
        current_hash = h.digest()             # 保存新哈希，给前一块使用

    # 5. 返回最终的根哈希（十六进制字符串格式）
    return current_hash.hex()

if __name__ == "__main__":
    # 验证 test.mp4 哈希是否正确
    test_hash = compute_hash_chain("test.mp4")
    print("test.mp4 哈希：", test_hash)

    # 计算 intro.mp4 的最终答案
    intro_hash = compute_hash_chain("intro.mp4")
    print("intro.mp4 答案：", intro_hash)


