from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii

backend = default_backend()

def pkcs7_unpad(data):
    """
    CBC模式去填充：PKCS#7
    :param data: 去填充前的字节串
    :return: 去填充后的字节串
    """
    padding_len = data[-1]
    return data[:-padding_len]

def aes_cbc_decrypt(key_hex, ciphertext_hex):
    """
    手动实现AES-CBC解密（符合实验步骤）
    步骤：提取IV → ECB解密分组 → 与前一分组异或 → 去填充
    """
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)

    # 1. 提取前16字节为IV
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    # 2. 初始化ECB解密器
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    plaintext_blocks = []
    # 3. 分组解密并异或
    for i in range(0, len(actual_ciphertext), 16):
        block = actual_ciphertext[i:i+16]
        decrypted_block = decryptor.update(block)

        # 第一个分组与IV异或，后续与前一个密文分组异或
        if i == 0:
            prev_block = iv
        else:
            prev_block = actual_ciphertext[i-16:i]

        plain_block = bytes([b ^ p for b, p in zip(decrypted_block, prev_block)])
        plaintext_blocks.append(plain_block)

    # 4. 拼接并去填充
    plaintext = b''.join(plaintext_blocks)
    plaintext = pkcs7_unpad(plaintext)
    return plaintext.decode('utf-8')

def aes_ctr_decrypt(key_hex, ciphertext_hex):
    """
    手动实现AES-CTR解密（符合实验步骤）
    步骤：提取初始计数器 → 加密计数器生成密钥流 → 异或解密
    """
    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)

    # 1. 提取前16字节为初始计数器
    counter = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    # 2. 初始化ECB加密器（用于生成密钥流）
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    plaintext = b''
    # 3. 生成密钥流并异或
    for i in range(0, len(actual_ciphertext), 16):
        block = actual_ciphertext[i:i+16]
        keystream_block = encryptor.update(counter)

        # 异或解密
        plain_block = bytes([b ^ k for b, k in zip(block, keystream_block)])
        plaintext += plain_block

        # 计数器递增（大端序）
        counter = (int.from_bytes(counter, byteorder='big') + 1).to_bytes(16, byteorder='big')

    return plaintext.decode('utf-8')

if __name__ == "__main__":
    # 题目参数（与截图完全一致）
    # 第1题 CBC
    key1 = "140b41b22a29beb4061bda66b6747e14"
    c1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad87883d04e008a7897"
    # 第2题 CBC
    key2 = "140b41b22a29beb4061bda66b6747e14"
    c2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48"
    # 第3题 CTR
    key3 = "36f18357be4dbd77f050515c73fcf9f2"
    c3 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc"
    # 第4题 CTR
    key4 = "36f18357be4dbd77f050515c73fcf9f2"
    c4 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa"

    # 执行解密并打印
    print("===== Lab4 解密答案 =====")
    print(f"第1题 (CBC):\n{aes_cbc_decrypt(key1, c1)}\n")
    print(f"第2题 (CBC):\n{aes_cbc_decrypt(key2, c2)}\n")
    print(f"第3题 (CTR):\n{aes_ctr_decrypt(key3, c3)}\n")
    print(f"第4题 (CTR):\n{aes_ctr_decrypt(key4, c4)}")