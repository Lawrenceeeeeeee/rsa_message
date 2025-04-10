import json
import base64
import time
import hashlib
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def generate_rsa_key_pair(private_key_path='private.pem', public_key_path='public.pem'):
    """生成RSA密钥对"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # 保存私钥
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_path, 'wb') as f:
        f.write(private_pem)

    # 保存公钥
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_path, 'wb') as f:
        f.write(public_pem)

def encrypt_message(message, public_key_path):
    """使用公钥加密消息"""
    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    message_bytes = message.encode('utf-8')
    
    # 加密消息
    ciphertext = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 构建输出数据
    return json.dumps({
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "timestamp": time.time(),
        "hash": hashlib.sha256(message_bytes).hexdigest()
    }, indent=2)

def decrypt_message(json_data, private_key_path):
    """使用私钥解密消息"""
    data = json.loads(json_data)
    
    # 加载私钥
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    # 解密消息
    plaintext_bytes = private_key.decrypt(
        base64.b64decode(data['ciphertext']),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 验证哈希值
    if hashlib.sha256(plaintext_bytes).hexdigest() != data['hash']:
        raise ValueError("消息完整性验证失败！")
    
    return plaintext_bytes.decode('utf-8')

def main():
    """命令行接口"""
    parser = argparse.ArgumentParser(description='RSA加密/解密工具')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # 生成密钥对命令
    gen_parser = subparsers.add_parser('generate', help='生成RSA密钥对')
    gen_parser.add_argument('--private', default='private.pem', help='私钥保存路径')
    gen_parser.add_argument('--public', default='public.pem', help='公钥保存路径')

    # 加密命令
    enc_parser = subparsers.add_parser('encrypt', help='加密消息')
    enc_parser.add_argument('--message', required=True, help='要加密的消息')
    enc_parser.add_argument('--public-key', required=True, help='公钥文件路径')
    enc_parser.add_argument('--output', help='输出文件路径')

    # 解密命令
    dec_parser = subparsers.add_parser('decrypt', help='解密消息')
    dec_parser.add_argument('--input', required=True, help='输入文件路径')
    dec_parser.add_argument('--private-key', required=True, help='私钥文件路径')

    args = parser.parse_args()

    if args.command == 'generate':
        generate_rsa_key_pair(args.private, args.public)
        print(f"密钥对生成成功：{args.private}, {args.public}")
    
    elif args.command == 'encrypt':
        result = encrypt_message(args.message, args.public_key)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(result)
            print(f"加密结果已保存至：{args.output}")
        else:
            print("加密结果：")
            print(result)
    
    elif args.command == 'decrypt':
        with open(args.input, 'r') as f:
            data = f.read()
        try:
            plaintext = decrypt_message(data, args.private_key)
            print("解密成功！明文内容：")
            print(plaintext)
        except ValueError as e:
            print(f"解密失败：{str(e)}")

if __name__ == '__main__':
    main()