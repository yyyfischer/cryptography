Lab4：AES CBC 模式与 CTR 模式加解密实现

一、实验目的

1. 掌握 AES 分组密码的基本原理，理解 CBC 与 CTR 两种工作模式的加密逻辑。

2. 手动实现 AES-CBC 和 AES-CTR 模式的解密流程，熟悉分组密码的分组处理、异或运算及密钥流生成机制。

3. 掌握 PKCS#7 填充与去填充规则，理解不同工作模式的特性差异。

二、解密答案

1. 第1题（CBC 模式解密）

◦ 密钥：140b41b22a29beb4061bda66b6747e14

◦ 密文：4ca00ff4c898d61e1edbf1800618fb2828a226d160dad87883d04e008a7897

◦ 答案：Basic CBC mode encryption needs padding.

2. 第2题（CBC 模式解密）

◦ 密钥：140b41b22a29beb4061bda66b6747e14

◦ 密文：5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48

◦ 答案：Our implementation uses random IV and PKCS #7 padding

3. 第3题（CTR 模式解密）

◦ 密钥：36f18357be4dbd77f050515c73fcf9f2

◦ 密文：69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc

◦ 答案：CTR mode lets you build a stream cipher from a block cipher.

4. 第4题（CTR 模式解密）

◦ 密钥：36f18357be4dbd77f050515c73fcf9f2

◦ 密文：770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa

◦ 答案：Always avoid the two time pad!

三、代码实现说明

1. PKCS#7 去填充函数 (pkcs7_unpad)

◦ 功能：移除 CBC 模式解密后最后一个分组的填充字节，保证明文长度符合原始长度。

◦ 原理：填充值等于填充字节的长度，即最后一个字节为 n，则最后 n 个字节均为 n。

2. AES-CBC 解密实现 (aes_cbc_decrypt)

◦ 提取 IV：密文前 16 字节为初始化向量，剩余为实际密文。

◦ 分组解密：使用 AES-ECB 模式逐个解密密文分组（ECB 为基础原语）。

◦ 异或还原：第 1 个明文分组 = ECB 解密结果 ⊕ IV；后续分组 = ECB 解密结果 ⊕ 前一个密文分组。

◦ 去填充：拼接所有明文分组后，调用 pkcs7_unpad 去除填充。

3. AES-CTR 解密实现 (aes_ctr_decrypt)

◦ 提取计数器：密文前 16 字节为初始计数器值（Initial Counter）。

◦ 生成密钥流：对递增的计数器值（初始值 + 步长 1）进行 AES-ECB 加密，生成对应长度的密钥流。

◦ 异或解密：密钥流与密文逐字节异或得到明文，CTR 模式无需填充且支持并行处理。

四、实验总结

本实验成功实现了 AES 两种典型工作模式的解密逻辑。通过手动实现，深入理解了 CBC 模式依赖分组链接和填充保证安全性，而 CTR 模式将分组密码转化为流密码，具有无需填充、支持并行运算的特点。代码严格遵循实验步骤，确保了逻辑的正确性和可验证性。