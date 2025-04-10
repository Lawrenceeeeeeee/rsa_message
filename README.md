# RSA Message

使用方法：

1. 生成密钥对：
```bash
python rsa_tool.py generate --private private.pem --public public.pem
```

1. 加密消息：
```bash
python rsa_tool.py encrypt --message "秘密信息" --public-key public.pem --output encrypted.json
```

1. 解密消息：
```bash
python rsa_tool.py decrypt --input encrypted.json --private-key private.pem
```

功能说明：
1. 使用RSA-OAEP加密方案，SHA-256作为哈希算法
2. 自动生成时间戳和消息哈希值
3. 输出格式为包含base64编码密文、时间戳和哈希值的JSON
4. 解密时自动验证消息完整性
5. 支持命令行操作，包含密钥生成、加密和解密功能

注意事项：
1. 消息长度限制：RSA 2048最大加密长度约为245字节
2. 需要安装cryptography库：`pip install cryptography`
3. 私钥文件需要妥善保管，建议设置密码保护（代码中未实现，可自行添加）