import hashlib
import random
import time
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# 哈希数据
def hash_data(data):
    return hashlib.sha256(data).hexdigest()


# 构建Merkle树，返回树的所有层
def build_merkle_tree(leaves):
    tree = []
    current_level = [hash_data(leaf) for leaf in leaves]
    tree.append(current_level)

    # 自底向上构建树
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                combined = current_level[i] + current_level[i + 1]
            else:
                combined = current_level[i] + current_level[i]
            next_level.append(hash_data(combined.encode()))
        tree.append(next_level)
        current_level = next_level

    return tree


# 获取认证路径
def get_authentication_path(index, tree):
    path = []
    for level in range(len(tree) - 1):
        sibling_index = index ^ 1
        if sibling_index < len(tree[level]):
            path.append(tree[level][sibling_index])
        index //= 2
    return path


# 签名验证
def verify_signature(public_key, message, signature):
    key = RSA.import_key(public_key)
    hash_message = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(hash_message, signature)
        return True
    except (ValueError, TypeError):
        return False


# 验证Merkle树根节点
def verify_merkle_root(leaf_hash, root, auth_path, index):
    current_hash = leaf_hash
    for sibling_hash in auth_path:
        if index % 2 == 0:
            current_hash = hash_data((current_hash + sibling_hash).encode())
        else:
            current_hash = hash_data((sibling_hash + current_hash).encode())
        index //= 2
    return current_hash == root


# 参数设置
h = 12  # Merkle树的高度
num_keys = 2 ** 12  # 密钥对数量

start_time = time.time()
# 生成 RSA 密钥对（One-Time Signature）
keys = [RSA.generate(2048) for _ in range(num_keys)]
public_keys = [key.publickey().export_key() for key in keys]

# 生成Merkle树并获取根节点
merkle_tree = build_merkle_tree(public_keys)
merkle_root = merkle_tree[-1][0]
print("Merkle Root:", merkle_root)
end_time = time.time()
merkle_tree_gen_time = end_time - start_time

n = 100
signature_gen_time = 0
merkle_ver_time = 0
for i in range(n):
    start_time = time.time()
    # 随机选择一个密钥对用于签名
    random_index = random.randint(0, num_keys - 1)
    private_key = keys[random_index]
    public_key = public_keys[random_index]
    message = b"User message to be signed"
    # 签名生成 (SIG)
    hash_message = SHA256.new(message)
    signature = pkcs1_15.new(private_key).sign(hash_message)
    # 输出签名信息
    print("Message:", message)
    print("Signature:", signature.hex())
    # 获取认证路径
    authentication_path = get_authentication_path(random_index, merkle_tree)
    end_time = time.time()
    print("Authentication Path:", authentication_path)
    signature_gen_time += end_time - start_time

    start_time = time.time()
    # 验证签名 (VER)
    verification_result = verify_signature(public_key, message, signature)
    print("Signature Verification:", "Success" if verification_result else "Failed")
    # 验证Merkle树根节点
    user_leaf_hash = hash_data(public_key)
    merkle_verification = verify_merkle_root(user_leaf_hash, merkle_root, authentication_path, random_index)
    end_time = time.time()
    print("Merkle Root Verification:", "Success" if merkle_verification else "Failed")
    merkle_ver_time += end_time - start_time

print(f"Merkle Tree Generation Time: {merkle_tree_gen_time:.4f} s")
print(f"Signature Generation Time: {signature_gen_time / n * 1000:.4f} ms")
print(f"Merkle Root Verification Time: {merkle_ver_time / n * 1000:.4f} ms")
