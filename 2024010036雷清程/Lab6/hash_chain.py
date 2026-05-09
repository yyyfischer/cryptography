import hashlib

BLOCK_SIZE = 1024

def calculate_h0(file_path):
    """
    哈希链倒序计算函数
    1. 读取完整文件
    2. 按1024字节切分数据块
    3. 数据块整体倒序排列
    4. 从最后一块开始，链式 SHA256 迭代
    """
    with open(file_path, "rb") as f:
        file_data = f.read()

    block_list = []
    for i in range(0, len(file_data), BLOCK_SIZE):
        block = file_data[i:i+BLOCK_SIZE]
        block_list.append(block)
 
    block_list = list(reversed(block_list))

    current_hash = b""
    for blk in block_list:
        current_hash = hashlib.sha256(blk + current_hash).digest()

    return current_hash.hex()


if __name__ == "__main__":

    standard_hash = "03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8"

    test_file = "test.raw.mp4"
    target_file = "intor.raw.mp4"

    test_result = calculate_h0(test_file)
    print(f"测试文件计算哈希：{test_result}")
    print(f"算法校验是否通过：{test_result == standard_hash}")
    print("-" * 60)

    final_h0 = calculate_h0(target_file)
    print(f"===== 作业最终 h0 哈希答案 =====")
    print(final_h0)