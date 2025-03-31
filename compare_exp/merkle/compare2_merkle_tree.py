import os
import time
import random
import subprocess
import json
import psutil
import signal
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# 常量定义（基于实测带宽1000Mbps）
BASE_BANDWIDTH = 1000  # 单位：Mbps
MONITOR_INTERVAL = 2  # 资源监控采样间隔(秒)


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


class ResourceLimiter:
    """增强版资源限制管理器"""

    @staticmethod
    def apply_cpu_limit(limit_percent):
        """安全CPU限制实现"""
        pid = os.getpid()
        cmd = [
            "cpulimit", "-l", str(limit_percent),
            "-p", str(pid), "-z", "-b"  # -z参数避免终端挂起
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid  # 创建新进程组
        )
        time.sleep(1)  # 等待稳定限制
        return proc

    @staticmethod
    def apply_bandwidth_limit(target_rate_mbit):
        """动态带宽限制（基于基准带宽比例）"""
        interface = "eth0"
        rate_percent = min(100, (target_rate_mbit / BASE_BANDWIDTH) * 100)

        # 清除旧规则
        subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"],
                       stderr=subprocess.DEVNULL)

        # 设置新规则（含突发带宽配置）
        cmds = [
            f"tc qdisc add dev {interface} root handle 1: htb",
            f"tc class add dev {interface} parent 1: classid 1:1 htb "
            f"rate {target_rate_mbit}mbit ceil {target_rate_mbit * 1.2}mbit burst 15k",
            f"tc filter add dev {interface} protocol ip parent 1: prio 1 u32 "
            f"match ip dst 0.0.0.0/0 flowid 1:1"
        ]
        for cmd in cmds:
            subprocess.run(cmd.split(), check=True)

        return interface

    @staticmethod
    def release_limits(proc, interface=None):
        """原子化资源释放"""
        if proc:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        if interface:
            subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"],
                           stderr=subprocess.DEVNULL)


import time
import psutil
from threading import Thread, Event


def monitor_resources(interval):
    """
    增强版资源监控装饰器（修正带宽计算问题）

    参数:
        interval (float): 采样间隔(秒)，默认1秒

    返回:
        装饰器函数，自动注入监控数据到函数返回值

    功能特性:
        1. 精确的带宽差值计算（单位：Mbps）
        2. 线程安全的监控数据收集
        3. 自动处理时间间隔异常
        4. 支持CPU/带宽实时监控
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            # 初始化数据结构
            monitor_data = {
                'timestamps': [],
                'cpu_usage': [],
                'bandwidth': []
            }

            # 资源基准值（线程安全设计）
            class Counter:
                __slots__ = ['io', 'time']

                def __init__(self):
                    self.io = psutil.net_io_counters()
                    self.time = time.time()

            counter = Counter()
            stop_event = Event()

            def monitoring_loop():
                while not stop_event.is_set():
                    try:
                        # 获取当前状态
                        curr_io = psutil.net_io_counters()
                        curr_time = time.time()
                        elapsed = curr_time - counter.time

                        # 有效数据检查
                        if elapsed >= 0.1:  # 最小有效间隔
                            # 计算真实带宽（Mbps）
                            delta = (curr_io.bytes_sent - counter.io.bytes_sent) + \
                                    (curr_io.bytes_recv - counter.io.bytes_recv)
                            bw_mbps = delta * 8 / elapsed / 1e6

                            # 记录数据（线程安全操作）
                            monitor_data['timestamps'].append(time.strftime("%H:%M:%S"))
                            monitor_data['cpu_usage'].append(psutil.cpu_percent(interval=None))
                            monitor_data['bandwidth'].append(min(bw_mbps, 10000))  # 限制最大值

                            # 更新基准值
                            counter.io = curr_io
                            counter.time = curr_time

                    except Exception as e:
                        print(f"[监控异常] {str(e)}")

                    # 精确间隔控制
                    sleep_time = max(0, interval - (time.time() - curr_time))
                    time.sleep(sleep_time)

                    # 启动监控线程

            monitor_thread = Thread(target=monitoring_loop, daemon=True)
            monitor_thread.start()

            try:
                result = func(*args, **kwargs)
                if isinstance(result, dict):
                    result['monitor_data'] = monitor_data
                return result
            finally:
                stop_event.set()
                monitor_thread.join(timeout=2)

        return wrapper

    return decorator


@monitor_resources(MONITOR_INTERVAL)
def run_performance_test(TEST_CASES):
    results = {
        'scenarios': [],
        'resource_limits': []
    }

    for case in TEST_CASES:
        scenario = {
            'desc': case['desc'],
            'metrics': {
                'tree_build': [],
                'sign_operations': [],
                'sign_verify': [],
                'merkle_verify': []
            },
            'resource_limits': {
                'target_cpu': case['cpu'] * 100,
                'target_bandwidth': case['bandwidth']
            }
        }

        # 应用资源限制
        cpu_limiter = ResourceLimiter.apply_cpu_limit(case['cpu'] * 100)
        bw_interface = ResourceLimiter.apply_bandwidth_limit(case['bandwidth'])

        try:
            for _ in range(2):  # 循环测试
                # 1. Merkle树构建（每次循环重新构建）
                start = time.perf_counter()
                keys = [RSA.generate(2048) for _ in range(64)]
                public_keys = [k.publickey().export_key() for k in keys]
                tree = build_merkle_tree(public_keys)
                scenario['metrics']['tree_build'].append(time.perf_counter() - start)

                # 2. 签名生成
                start = time.perf_counter()
                message = b"Test Message"
                random_index = random.randint(0, 63)
                sig = pkcs1_15.new(keys[random_index]).sign(SHA256.new(message))
                scenario['metrics']['sign_operations'].append(
                    (time.perf_counter() - start) * 1000)  # 转毫秒

                # 3. 签名验证
                start = time.perf_counter()
                pkcs1_15.new(keys[random_index].publickey()).verify(
                    SHA256.new(message), sig)
                scenario['metrics']['sign_verify'].append(
                    (time.perf_counter() - start) * 1000)

                # 4. Merkle验证
                auth_path = get_authentication_path(random_index, tree)
                leaf_hash = hash_data(public_keys[random_index])
                start = time.perf_counter()
                verify_merkle_root(leaf_hash, tree[-1][0], auth_path, random_index)
                scenario['metrics']['merkle_verify'].append(
                    (time.perf_counter() - start) * 1000)

            # 计算平均耗时（保留4位小数）
            for metric in scenario['metrics']:
                if scenario['metrics'][metric]:
                    scenario['metrics'][metric] = round(
                        sum(scenario['metrics'][metric]) / len(scenario['metrics'][metric]), 4)

        except Exception as e:
            print(f"测试中断: {case['desc']} - {str(e)}")
            scenario['error'] = str(e)
        finally:
            ResourceLimiter.release_limits(cpu_limiter, bw_interface)
            results['scenarios'].append(scenario)

    return results


# 测试用例（动态调整带宽限制）
TEST_CASES = [
    {"cpu": 1.0, "bandwidth": BASE_BANDWIDTH, "desc": "Unconstrained"},
    {"cpu": 0.7, "bandwidth": BASE_BANDWIDTH * 0.7, "desc": "Mobile Device"},
    {"cpu": 0.4, "bandwidth": BASE_BANDWIDTH * 0.4, "desc": "IoT Device"},
    {"cpu": 0.2, "bandwidth": BASE_BANDWIDTH * 0.2, "desc": "Harsh Environment"}
]

if __name__ == "__main__":
    data = run_performance_test(TEST_CASES)
    with open('perf_report.json', 'w') as f:
        json.dump(data, f, indent=2)
    print("测试完成，报告已保存到perf_report.json")
