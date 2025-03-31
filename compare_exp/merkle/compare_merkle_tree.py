"""
Merkle Tree Authentication Scheme with Resource Constraints Evaluation 
Created: 2025-03-31 09:10 
"""
import hashlib
import random
import time
import psutil
import matplotlib.pyplot as plt
import json
import seaborn as sns
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from functools import wraps



# ========================
# 核心功能模块 
# ========================

class ResourceSimulator:
    """资源限制模拟器"""

    def __init__(self, cpu_limit=1.0, bandwidth_kbps=1000):
        self.cpu_limit = cpu_limit
        self.bandwidth = bandwidth_kbps

    def __call__(self, func):
        @wraps(func)
        def wrapped(*args, **kwargs):
            # CPU限制模拟 
            start_time = time.time()
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time

            if self.cpu_limit < 1.0:
                throttle_time = elapsed * (1 / self.cpu_limit - 1)
                time.sleep(throttle_time)

                # 带宽限制模拟
            if self.bandwidth < 1000 and result:
                if isinstance(result, (str, bytes)):
                    data_size = len(result)
                elif hasattr(result, '__len__'):
                    data_size = len(str(result))
                else:
                    data_size = 100  # 默认假设100字节 

                transmit_time = (data_size * 8) / (self.bandwidth * 1024)
                time.sleep(transmit_time)

            return result

        return wrapped


def hash_data(data):
    """SHA-256哈希函数"""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def build_merkle_tree(leaves):
    """构建Merkle树"""
    tree = [[hash_data(leaf) for leaf in leaves]]

    while len(tree[-1]) > 1:
        current_level = tree[-1]
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            next_level.append(hash_data(left + right))
        tree.append(next_level)

    return tree


def get_authentication_path(index, tree):
    """获取认证路径"""
    path = []
    for level in tree[:-1]:
        sibling_index = index ^ 1
        if sibling_index < len(level):
            path.append(level[sibling_index])
        index = index // 2
    return path


def verify_signature(public_key, message, signature):
    key = RSA.import_key(public_key)
    hash_message = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(hash_message, signature)
        return True
    except (ValueError, TypeError):
        return False


def verify_merkle_root(leaf, root, path, index):
    """验证Merkle根"""
    current_hash = leaf
    for sibling in path:
        if index % 2 == 0:
            current_hash = hash_data(current_hash + sibling)
        else:
            current_hash = hash_data(sibling + current_hash)
        index = index // 2
    return current_hash == root


# ========================
# 性能评估模块 
# ========================

def performance_test():
    """综合性能测试"""
    # 测试配置 
    TEST_CASES = [
        {"cpu": 1.0, "bandwidth": 1000, "desc": "无限制"},
        {"cpu": 0.7, "bandwidth": 700, "desc": "移动设备"},
        {"cpu": 0.4, "bandwidth": 400, "desc": "IoT设备"},
        {"cpu": 0.2, "bandwidth": 200, "desc": "极端环境"}
    ]

    results = {
        'tree_build': [],  # 包含密钥生成+建树时间
        'sign_generate': [],  # 密钥查找+签名生成时间
        'sign_verify': [],  # 签名验证时间
        'merkle_verify': [],  # Merkle验证时间
        'cpu_usage': []  # 每次测试的CPU负载
    }

    for case in TEST_CASES:
        print(f"\n测试场景: {case['desc']}")
        simulator = ResourceSimulator(case['cpu'], case['bandwidth'])

        # ========================
        # 1. 动态生成密钥并构建Merkle树（全流程压测）
        # ========================
        @simulator
        def full_merkle_process():
            # 密钥生成（受资源限制）
            num_keys = 256
            keys = [RSA.generate(2048) for _ in range(num_keys)]
            public_keys = [key.publickey().export_key() for key in keys]

            # 建树操作（同受资源限制）
            tree = build_merkle_tree(public_keys)
            return keys, public_keys, tree

        start_tree = time.time()
        keys, public_keys, tree = full_merkle_process()
        results['tree_build'].append((time.time() - start_tree) * 1000)

        # ========================
        # 2. 签名生成与验证（动态选择密钥）
        # ========================
        random_index = random.randint(0, len(keys) - 1)
        message = b"Test message"

        # 2.1 签名生成（含密钥查找）
        @simulator
        def sign_operation():
            private_key = keys[random_index]  # 模拟密钥查找开销
            return pkcs1_15.new(private_key).sign(SHA256.new(message))

        start_sign = time.time()
        sig = sign_operation()
        results['sign_generate'].append((time.time() - start_sign) * 1000)

        # 2.2 签名验证
        @simulator
        def verify_operation():
            pkcs1_15.new(keys[random_index].publickey()).verify(SHA256.new(message), sig)

        start_verify = time.time()
        try:
            verify_operation()
            print("Signature Verification: Success")
        except Exception as e:
            print(f"Signature Failed: {str(e)}")
        results['sign_verify'].append((time.time() - start_verify) * 1000)

        # ========================
        # 3. Merkle验证（动态路径计算）
        # ========================
        @simulator
        def merkle_verify_flow():
            auth_path = get_authentication_path(random_index, tree)
            leaf_hash = hash_data(public_keys[random_index])
            return verify_merkle_root(leaf_hash, tree[-1][0], auth_path, random_index)

        start_merkle = time.time()
        print("Merkle Verify:", "Success" if merkle_verify_flow() else "Failed")
        results['merkle_verify'].append((time.time() - start_merkle) * 1000)

        # 记录CPU负载
        results['cpu_usage'].append(psutil.cpu_percent(interval=1))

    print(json.dumps(results, indent=4))
    # 可视化结果
    # visualize_results(TEST_CASES, results)

# def visualize_results(cases, results):
#     """结果可视化"""
#     labels = [case['desc'] for case in cases]
#
#     plt.figure(figsize=(12, 8))
#
#     # 时延图表
#     plt.subplot(2, 2, 1)
#     plt.plot(labels, results['tree_build'], 'o-', label='Merkle Tree Build')
#     plt.plot(labels, results['sign_verify'], 's-', label='Signature Verify')
#     plt.plot(labels, results['merkle_verify'], 'd-', label='Merkle Verify')
#     plt.ylabel('Time  (s)')
#     plt.title('Operation  Latency')
#     plt.legend()
#     plt.grid()
#
#     # CPU使用率
#     plt.subplot(2, 2, 2)
#     plt.bar(labels, results['cpu_usage'])
#     plt.ylabel('CPU  Usage (%)')
#     plt.title('Resource  Utilization')
#     plt.grid()
#
#     # 性能降级分析
#     plt.subplot(2, 1, 2)
#     degradation = [
#         (results['tree_build'][-1] / results['tree_build'][0] - 1) * 100,
#         (results['sign_verify'][-1] / results['sign_verify'][0] - 1) * 100,
#         (results['merkle_verify'][-1] / results['merkle_verify'][0] - 1) * 100
#     ]
#     plt.bar(['Tree  Build', 'Signature', 'Merkle Verify'], degradation)
#     plt.ylabel('Performance  Degradation (%)')
#     plt.title('Extreme  Environment Impact')
#     plt.grid()
#
#     plt.tight_layout()
#     plt.savefig('performance_analysis.png')
#     print("性能分析图表已保存为 performance_analysis.png")


def visualize_results(cases, results):
    """改进可视化风格"""
    sns.set_theme(style="whitegrid")
    labels = [case['desc'] for case in cases]

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))

    # 时延曲线
    sns.lineplot(x=labels, y=results['tree_build'], marker="o", label="Merkle Tree Build", ax=axes[0, 0])
    sns.lineplot(x=labels, y=results['sign_verify'], marker="s", label="Signature Verify", ax=axes[0, 0])
    sns.lineplot(x=labels, y=results['merkle_verify'], marker="d", label="Merkle Verify", ax=axes[0, 0])
    axes[0, 0].set_title("操作延迟")

    # CPU 使用率
    sns.barplot(x=labels, y=results['cpu_usage'], ax=axes[0, 1])
    axes[0, 1].set_title("CPU 资源利用率")

    # 性能降级
    degradation = [
        (results['tree_build'][-1] / results['tree_build'][0] - 1) * 100,
        (results['sign_verify'][-1] / results['sign_verify'][0] - 1) * 100,
        (results['merkle_verify'][-1] / results['merkle_verify'][0] - 1) * 100
    ]
    sns.barplot(x=['Tree Build', 'Signature', 'Merkle Verify'], y=degradation, ax=axes[1, 0])
    axes[1, 0].set_title("性能降级 (%)")

    plt.tight_layout()
    plt.savefig('performance_analysis.png')
    print("性能分析图表已保存")


# ========================
# 主执行流程 
# ========================

if __name__ == "__main__":
    # 示例基础功能 
    print("\n[基础功能演示]")
    keys = [RSA.generate(2048) for _ in range(4)]
    pub_keys = [key.publickey().export_key() for key in keys]

    tree = build_merkle_tree(pub_keys)
    tree_root = tree[-1][0]
    print("Merkle Root:", tree_root)

    # 随机选择一个密钥对用于签名
    random_index = random.randint(0, 4 - 1)
    private_key = keys[random_index]
    public_key = pub_keys[random_index]
    message = b"User message to be signed"
    # 签名生成 (SIG)
    hash_message = SHA256.new(message)
    signature = pkcs1_15.new(private_key).sign(hash_message)
    # 输出签名信息
    print("Message:", message)
    print("Signature:", signature.hex())
    # 获取认证路径
    authentication_path = get_authentication_path(random_index, tree)
    end_time = time.time()
    print("Authentication Path:", authentication_path)

    # 验证签名 (VER)
    verification_result = verify_signature(public_key, message, signature)
    print("Signature Verification:", "Success" if verification_result else "Failed")
    # 验证Merkle树根节点
    user_leaf_hash = hash_data(public_key)
    merkle_verification = verify_merkle_root(user_leaf_hash, tree_root, authentication_path, random_index)
    print("Merkle Root Verification:", "Success" if merkle_verification else "Failed")

    # 完整性能测试
    print("\n[启动性能评估]")
    performance_test()
