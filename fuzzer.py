from __future__ import annotations
import os
import sys
import time
import json
import socket
import signal
import random
import struct
import psutil
import hashlib
import argparse
import resource
import threading
import subprocess
import multiprocessing
from typing import Dict, Set, List, Optional, Union, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
import logging
import numpy as np
from abc import ABC, abstractmethod

# 네트워크 프로토콜 퍼징을 위한 상수들
DEFAULT_PORT = 8000
MAX_PACKET_SIZE = 65535

# 유전 알고리즘 파라미터
POPULATION_SIZE = 100
MUTATION_RATE = 0.1
CROSSOVER_RATE = 0.8

@dataclass
class FuzzStats:
    """퍼징 통계"""
    start_time: float = time.time()
    total_execs: int = 0
    unique_crashes: int = 0
    unique_hangs: int = 0
    unique_paths: int = 0
    last_path: float = time.time()
    last_crash: float = time.time()
    cycles: int = 0
    executions_per_sec: float = 0.0
    coverage_percent: float = 0.0
    avg_exec_time: float = 0.0
    total_nodes: int = 0
    edge_coverage: Dict[int, int] = None

    def to_dict(self):
        return asdict(self)

class Sandbox:
    """샌드박스 실행 환경"""
    def __init__(self, 
                 memory_limit: int = 1024,  # MB
                 cpu_timeout: int = 1,      # seconds
                 allow_network: bool = False):
        self.memory_limit = memory_limit
        self.cpu_timeout = cpu_timeout
        self.allow_network = allow_network

    def setup_limits(self):
        """리소스 제한 설정"""
        # CPU 시간 제한
        resource.setrlimit(resource.RLIMIT_CPU, (self.cpu_timeout, self.cpu_timeout))
        
        # 메모리 제한
        memory_bytes = self.memory_limit * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        
        # 파일 디스크립터 제한
        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        
        if not self.allow_network:
            # 네트워크 접근 차단
            def block_socket(*args, **kwargs):
                raise socket.error("Network access denied in sandbox")
            socket.socket = block_socket

    def run(self, cmd: List[str], input_data: bytes = None) -> Tuple[int, bytes, bytes]:
        """샌드박스에서 명령어 실행"""
        def target():
            self.setup_limits()
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE if input_data else None
            )
            
            try:
                stdout, stderr = process.communicate(input=input_data, timeout=self.cpu_timeout)
                return process.returncode, stdout, stderr
            except subprocess.TimeoutExpired:
                process.kill()
                raise
                
        # 별도 프로세스에서 실행
        process = multiprocessing.Process(target=target)
        process.start()
        process.join(timeout=self.cpu_timeout + 0.5)
        
        if process.is_alive():
            process.terminate()
            process.join()
            raise TimeoutError("Process execution timed out")
            
        return process.exitcode, b"", b""  # 실제 출력은 프로세스 내에서만 접근 가능

class NetworkFuzzer:
    """네트워크 프로토콜 퍼저"""
    def __init__(self, host: str, port: int, protocol: str = "tcp"):
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.timeout = 1.0
        
    def send_payload(self, data: bytes) -> Tuple[bool, bytes]:
        """페이로드 전송"""
        try:
            if self.protocol == "tcp":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.connect((self.host, self.port))
                    sock.send(data)
                    response = sock.recv(MAX_PACKET_SIZE)
                    return True, response
                    
            elif self.protocol == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.sendto(data, (self.host, self.port))
                    response, _ = sock.recvfrom(MAX_PACKET_SIZE)
                    return True, response
                    
        except socket.timeout:
            return False, b"Timeout"
        except Exception as e:
            return False, str(e).encode()
            
        return False, b"Unknown error"

    def fuzz_protocol(self, 
                     base_packets: List[bytes],
                     num_iterations: int = 1000) -> List[Tuple[bytes, bytes]]:
        """프로토콜 퍼징"""
        interesting_cases = []
        
        for _ in range(num_iterations):
            # 기본 패킷 선택 및 변이
            packet = random.choice(base_packets)
            mutated = self._mutate_packet(packet)
            
            # 전송 및 응답 확인
            success, response = self.send_payload(mutated)
            
            # 흥미로운 응답 저장
            if not success or len(response) > len(packet) * 2 or b"error" in response.lower():
                interesting_cases.append((mutated, response))
                
        return interesting_cases

    def _mutate_packet(self, data: bytes) -> bytes:
        """패킷 변이"""
        mutators = [
            self._bit_flip,
            self._byte_flip,
            self._protocol_aware,
            self._length_mutation,
            self._header_mutation
        ]
        
        mutator = random.choice(mutators)
        return mutator(data)

    def _bit_flip(self, data: bytes) -> bytes:
        """비트 플립"""
        data = bytearray(data)
        num_flips = random.randint(1, max(1, len(data) // 100))
        
        for _ in range(num_flips):
            pos = random.randint(0, len(data) - 1)
            bit = random.randint(0, 7)
            data[pos] ^= (1 << bit)
            
        return bytes(data)

    def _byte_flip(self, data: bytes) -> bytes:
        """바이트 플립"""
        data = bytearray(data)
        num_flips = random.randint(1, max(1, len(data) // 50))
        
        for _ in range(num_flips):
            pos = random.randint(0, len(data) - 1)
            data[pos] ^= 0xFF
            
        return bytes(data)

    def _protocol_aware(self, data: bytes) -> bytes:
        """프로토콜 인식 변이"""
        # 일반적인 프로토콜 필드 변이
        special_values = [
            b"\x00" * 4,  # NULL
            b"\xFF" * 4,  # 모두 1
            b"A" * 100,   # 버퍼 오버플로우
            b"%s%n%x%d",  # 포맷 스트링
            b"../../../etc/passwd",  # 경로 순회
            b"><script>alert(1)</script>",  # XSS
            b"OR 1=1--",  # SQL 인젝션
        ]
        
        data = bytearray(data)
        if len(data) < 4:
            return bytes(data)
            
        pos = random.randint(0, len(data) - 4)
        value = random.choice(special_values)
        data[pos:pos + len(value)] = value
        
        return bytes(data)

    def _length_mutation(self, data: bytes) -> bytes:
        """길이 필드 변이"""
        data = bytearray(data)
        if len(data) < 4:
            return bytes(data)
            
        # 길이 필드로 보이는 부분 탐색
        for i in range(len(data) - 4):
            candidate = int.from_bytes(data[i:i+4], byteorder='big')
            if candidate > 0 and candidate < len(data):
                # 길이 필드 조작
                new_length = random.choice([
                    0,
                    0xFFFFFFFF,
                    len(data) * 2,
                    len(data) - 1
                ])
                data[i:i+4] = new_length.to_bytes(4, byteorder='big')
                break
                
        return bytes(data)

    def _header_mutation(self, data: bytes) -> bytes:
        """헤더 필드 변이"""
        if len(data) < 8:  # 최소 헤더 크기
            return data
            
        header_size = min(8, len(data) // 4)
        header = bytearray(data[:header_size])
        
        # 헤더 필드 변이
        num_mutations = random.randint(1, header_size)
        for _ in range(num_mutations):
            pos = random.randint(0, header_size - 1)
            header[pos] = random.randint(0, 255)
            
        return bytes(header) + data[header_size:]

class GeneticFuzzer:
    """유전 알고리즘 기반 퍼저"""
    def __init__(self, 
                 population_size: int = POPULATION_SIZE,
                 mutation_rate: float = MUTATION_RATE,
                 crossover_rate: float = CROSSOVER_RATE):
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self.population: List[Dict] = []
        self.generation = 0
        
    def initialize_population(self, seed_inputs: List[bytes]):
        """초기 개체군 생성"""
        self.population = []
        
        # 시드 입력으로 초기 개체군 생성
        for seed in seed_inputs:
            self.population.append({
                'data': seed,
                'fitness': 0.0,
                'coverage': set(),
                'age': 0
            })
            
        # 나머지는 변이로 생성
        while len(self.population) < self.population_size:
            seed = random.choice(seed_inputs)
            mutated = self._mutate(seed)
            self.population.append({
                'data': mutated,
                'fitness': 0.0,
                'coverage': set(),
                'age': 0
            })

    def evolve(self, coverage_function) -> List[bytes]:
        """한 세대 진화"""
        # 적합도 평가
        for individual in self.population:
            coverage = coverage_function(individual['data'])
            individual['coverage'] = coverage
            individual['fitness'] = len(coverage)
            individual['age'] += 1
            
        # 선택
        parents = self._select_parents()
        
        # 새로운 세대 생성
        new_population = []
        
        # 엘리트 보존
        elite_size = self.population_size // 10
        elite = sorted(self.population, key=lambda x: x['fitness'], reverse=True)[:elite_size]
        new_population.extend(elite)
        
        # 교차 및 변이
        while len(new_population) < self.population_size:
            if random.random() < self.crossover_rate and len(parents) >= 2:
                parent1 = random.choice(parents)
                parent2 = random.choice(parents)
                child = self._crossover(parent1['data'], parent2['data'])
            else:
                parent = random.choice(parents)
                child = self._mutate(parent['data'])
                
            new_population.append({
                'data': child,
                'fitness': 0.0,
                'coverage': set(),
                'age': 0
            })
            
        self.population = new_population
        self.generation += 1
        
        return [ind['data'] for ind in elite]

    def _select_parents(self) -> List[Dict]:
        """토너먼트 선택"""
        tournament_size = max(2, self.population_size // 5)
        num_parents = self.population_size // 2
        parents = []
        
        for _ in range(num_parents):
            tournament = random.sample(self.population, tournament_size)
            winner = max(tournament, key=lambda x: x['fitness'])
            parents.append(winner)
            
        return parents

    def _crossover(self, data1: bytes, data2: bytes) -> bytes:
        """교차"""
        # 1점 교차
        if len(data1) < 2 or len(data2) < 2:
            return data1
            
        point = random.randint(1, min(len(data1), len(data2)) - 1)
        child = data1[:point] + data2[point:]
        
        return child

    def _mutate(self, data: bytes) -> bytes:
        """변이"""
        if random.random() > self.mutation_rate:
            return data
            
        data = bytearray(data)
        num_mutations = random.randint(1, max(1, len(data) // 10))
        
        for _ in range(num_mutations):
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)
            
        return bytes(data)

class CompleteFuzzer:
    def __init__(self,
                 binary_path: str,
                 input_dir: str,
                 output_dir: str,
                 pin_tool: str,
                 mode: str = "file",
                 cores: int = None,
                 memory_limit: int = None,
                 timeout: int = 1):
                 
        self.binary_path = os.path.abspath(binary_path)
        self.input_dir = os.path.abspath(input_dir)
        self.output_dir = os.path.abspath(output_dir)
        self.pin_tool = os.path.abspath(pin_tool)
        self.mode = mode
        self.timeout = timeout
        
        # 리소스 설정
        self.cores = cores or multiprocessing.cpu_count() - 1
        self.memory_limit = memory_limit or (psutil.virtual_memory().available // (1024 * 1024))
        
        # 작업 디렉토리 구조
        self.setup_directories()
        
        # 컴포넌트 초기화
        self.sandbox = Sandbox(memory_limit=self.memory_limit, cpu_timeout=self.timeout)
        self.genetic_fuzzer = GeneticFuzzer()
        if mode == "network":
            self.network_fuzzer = NetworkFuzzer("localhost", DEFAULT_PORT)
        
        # 멀티프로세싱 관련
        self.manager = multiprocessing.Manager()
        self.queue = self.manager.list()
        self.stats = self.manager.dict(FuzzStats().__dict__)
        self.coverage_map = self.manager.dict()
        self.crashes = self.manager.list()
        
        # 동기화를 위한 락
        self.stats_lock = multiprocessing.Lock()
        self.queue_lock = multiprocessing.Lock()
        
        # AFL++ 영감 기능
        self.power_schedules = ['fast', 'explore', 'exploit', 'coe']
        self.current_schedule = 'fast'
        self.schedule_counters = {name: 0 for name in self.power_schedules}
        
        # 코드 커버리지 분석
        self.coverage_analyzer = CoverageAnalyzer(self.pin_tool)
        
        # 로깅 설정
        self.setup_logging()

    def setup_directories(self):
        """작업 디렉토리 구조 설정"""
        dirs = [
            "queue",          # 퍼징 큐
            "crashes",        # 크래시 케이스
            "hangs",         # 타임아웃 케이스
            "plots",         # 통계 그래프
            ".state",        # 상태 저장
            "analysis",      # 크래시 분석
            "minimized",     # 최소화된 테스트케이스
            "mutations",     # 변이 히스토리
            "synced"         # 동기화 데이터
        ]
        
        for d in dirs:
            path = os.path.join(self.output_dir, d)
            os.makedirs(path, exist_ok=True)

    def setup_logging(self):
        """로깅 설정"""
        log_path = os.path.join(self.output_dir, "fuzzer.log")
        
        self.logger = logging.getLogger("CompleteFuzzer")
        self.logger.setLevel(logging.INFO)
        
        # 파일 핸들러
        fh = logging.FileHandler(log_path)
        fh.setLevel(logging.INFO)
        
        # 콘솔 핸들러
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # 포맷터
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def start_fuzzing(self):
        """퍼징 시작"""
        self.logger.info("퍼징 시작...")
        
        # 초기 시드 로드
        self.load_initial_seeds()
        
        # 워커 프로세스 시작
        workers = []
        for i in range(self.cores):
            p = multiprocessing.Process(
                target=self.fuzzing_worker,
                args=(i,)
            )
            p.start()
            workers.append(p)
            
        # 모니터링 스레드 시작
        monitor = threading.Thread(target=self.monitoring_thread)
        monitor.daemon = True
        monitor.start()
        
        try:
            # 메인 루프
            while True:
                # 통계 업데이트
                self.update_stats()
                
                # 전력 스케줄 조정
                self.adjust_power_schedule()
                
                # 정기적인 상태 저장
                self.save_state()
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("퍼징 중단 요청 받음...")
            
        finally:
            # 정리
            for p in workers:
                p.terminate()
                p.join()
            
            self.save_state()
            self.generate_report()

    def fuzzing_worker(self, worker_id: int):
        """퍼징 워커 프로세스"""
        self.logger.info(f"Worker {worker_id} 시작")
        
        # 프로세스별 RNG 초기화
        random.seed(worker_id + int(time.time()))
        
        local_stats = {
            'executions': 0,
            'paths': 0,
            'crashes': 0
        }
        
        while True:
            # 큐에서 입력 선택
            input_entry = self.select_input()
            
            # 변이 전략 선택
            strategy = self.select_mutation_strategy()
            
            # 변이 실행
            for _ in range(strategy['mutations']):
                mutated = self.mutate(input_entry['data'], strategy)
                
                # 실행 및 모니터링
                result = self.run_target(mutated)
                
                with self.stats_lock:
                    self.stats['total_execs'] += 1
                    local_stats['executions'] += 1
                
                # 결과 분석
                if result['crash']:
                    self.handle_crash(mutated, result)
                    local_stats['crashes'] += 1
                    
                elif result['new_coverage']:
                    self.handle_new_coverage(mutated, result)
                    local_stats['paths'] += 1
                    
                # 에너지 조정
                self.adjust_energy(input_entry, result)
            
            # 주기적인 상태 보고
            if local_stats['executions'] % 1000 == 0:
                self.report_worker_stats(worker_id, local_stats)

    def select_mutation_strategy(self) -> Dict:
        """변이 전략 선택"""
        strategies = {
            'havoc': {
                'weight': 4,
                'mutations': lambda: random.randint(1, 32),
                'funcs': [
                    self.bit_flip,
                    self.byte_flip,
                    self.arithmetic,
                    self.interesting_values,
                    self.dictionary_replace,
                    self.block_operations
                ]
            },
            'splice': {
                'weight': 2,
                'mutations': lambda: random.randint(1, 8),
                'funcs': [
                    self.splice_inputs
                ]
            },
            'structured': {
                'weight': 3,
                'mutations': lambda: random.randint(1, 16),
                'funcs': [
                    self.header_mutation,
                    self.length_mutation,
                    self.checksum_mutation,
                    self.protocol_mutation
                ]
            }
        }
        
        # 가중치 기반 선택
        weights = [s['weight'] for s in strategies.values()]
        strategy_name = random.choices(list(strategies.keys()), weights=weights)[0]
        strategy = strategies[strategy_name]
        
        return {
            'name': strategy_name,
            'mutations': strategy['mutations'](),
            'funcs': strategy['funcs']
        }

    def run_target(self, input_data: bytes) -> Dict:
        """대상 프로그램 실행"""
        if self.mode == "file":
            return self.run_file_target(input_data)
        else:
            return self.run_network_target(input_data)

    def run_file_target(self, input_data: bytes) -> Dict:
        """파일 모드로 대상 실행"""
        # 임시 파일 생성
        tmp_path = os.path.join(self.output_dir, f".tmp_{os.getpid()}")
        with open(tmp_path, 'wb') as f:
            f.write(input_data)
            
        try:
            # PIN 도구로 실행
            cmd = [
                os.path.join(os.getenv("PIN_ROOT"), "pin"),
                "-t", self.pin_tool,
                "--",
                self.binary_path,
                tmp_path
            ]
            
            result = self.sandbox.run(cmd)
            
            coverage = self.coverage_analyzer.get_coverage()
            
            return {
                'crash': result[0] != 0,
                'timeout': False,
                'new_coverage': self.is_new_coverage(coverage),
                'coverage': coverage,
                'output': result[1],
                'error': result[2]
            }
            
        finally:
            os.unlink(tmp_path)

    def run_network_target(self, input_data: bytes) -> Dict:
        """네트워크 모드로 대상 실행"""
        success, response = self.network_fuzzer.send_payload(input_data)
        
        return {
            'crash': not success,
            'timeout': b"Timeout" in response,
            'new_coverage': len(response) > len(input_data) * 2,
            'coverage': set(),  # 네트워크 모드에서는 커버리지 수집이 제한적
            'output': response,
            'error': b""
        }

    def handle_crash(self, input_data: bytes, result: Dict):
        """크래시 처리"""
        crash_hash = self.hash_crash(input_data, result)
        
        with self.stats_lock:
            if crash_hash not in self.crashes:
                self.crashes.append(crash_hash)
                self.stats['unique_crashes'] += 1
                self.stats['last_crash'] = time.time()
                
                # 크래시 저장
                crash_path = os.path.join(
                    self.output_dir,
                    "crashes",
                    f"id_{crash_hash[:16]}"
                )
                
                with open(crash_path, 'wb') as f:
                    f.write(input_data)
                
                # 크래시 정보 저장
                info_path = crash_path + ".txt"
                with open(info_path, 'w') as f:
                    json.dump({
                        'time': time.ctime(),
                        'execution': self.stats['total_execs'],
                        'output': result['output'].decode(errors='ignore'),
                        'error': result['error'].decode(errors='ignore')
                    }, f, indent=2)
                
                # 크래시 분석 시작
                self.analyze_crash(input_data, result, crash_hash)

    def analyze_crash(self, input_data: bytes, result: Dict, crash_hash: str):
        """크래시 분석"""
        analysis_dir = os.path.join(self.output_dir, "analysis", crash_hash)
        os.makedirs(analysis_dir, exist_ok=True)
        
        # GDB를 통한 스택 트레이스 수집
        gdb_trace = self.get_gdb_trace(input_data)
        with open(os.path.join(analysis_dir, "stacktrace.txt"), 'w') as f:
            f.write(gdb_trace)
        
        # ASAN 출력 분석 (있는 경우)
        if b"AddressSanitizer" in result['error']:
            self.analyze_asan_output(result['error'], analysis_dir)
        
        # 최소화 시도
        minimized = self.minimize_crash(input_data, crash_hash)
        if minimized:
            with open(os.path.join(analysis_dir, "minimized"), 'wb') as f:
                f.write(minimized)
        
        # 유사한 크래시들과 비교
        self.compare_crashes(crash_hash, analysis_dir)

    def get_gdb_trace(self, input_data: bytes) -> str:
        """GDB로 스택 트레이스 수집"""
        tmp_path = os.path.join(self.output_dir, f".gdb_input_{os.getpid()}")
        with open(tmp_path, 'wb') as f:
            f.write(input_data)
            
        try:
            gdb_cmd = f"""
                set pagination off
                set logging on {tmp_path}.log
                run {tmp_path}
                bt full
                info registers
                quit
            """
            
            with open(f"{tmp_path}.gdb", 'w') as f:
                f.write(gdb_cmd)
            
            subprocess.run([
                "gdb",
                "--batch",
                "-x", f"{tmp_path}.gdb",
                self.binary_path
            ], capture_output=True)
            
            with open(f"{tmp_path}.log") as f:
                return f.read()
                
        finally:
            for ext in ['', '.gdb', '.log']:
                if os.path.exists(tmp_path + ext):
                    os.unlink(tmp_path + ext)

    def minimize_crash(self, input_data: bytes, crash_hash: str) -> Optional[bytes]:
        """크래시 케이스 최소화 (계속)"""
        min_data = input_data
        
        # 단일 바이트 제거 시도
        changed = True
        while changed:
            changed = False
            for i in range(len(min_data)):
                test_data = min_data[:i] + min_data[i+1:]
                result = self.run_target(test_data)
                
                if result['crash'] and self.hash_crash(test_data, result) == crash_hash:
                    min_data = test_data
                    changed = True
                    break
        
        # 특수값 치환 시도
        special_values = [b"\x00", b"\xff", b"A", b"0"]
        for i in range(len(min_data)):
            for val in special_values:
                test_data = min_data[:i] + val + min_data[i+1:]
                result = self.run_target(test_data)
                
                if result['crash'] and self.hash_crash(test_data, result) == crash_hash:
                    min_data = test_data
        
        return min_data if len(min_data) < len(input_data) else None

    def compare_crashes(self, crash_hash: str, analysis_dir: str):
        """유사한 크래시 비교 분석"""
        crashes_dir = os.path.join(self.output_dir, "crashes")
        current_trace = self.get_gdb_trace(crash_hash)
        similar_crashes = []
        
        for crash in os.listdir(crashes_dir):
            if not crash.startswith("id_"):
                continue
                
            other_hash = crash[3:19]  # id_ 제외한 해시값
            if other_hash == crash_hash:
                continue
                
            other_trace = self.get_gdb_trace(other_hash)
            similarity = self.compare_stack_traces(current_trace, other_trace)
            
            if similarity > 0.8:  # 80% 이상 유사
                similar_crashes.append({
                    'hash': other_hash,
                    'similarity': similarity
                })
        
        # 유사 크래시 정보 저장
        with open(os.path.join(analysis_dir, "similar_crashes.json"), 'w') as f:
            json.dump(similar_crashes, f, indent=2)

    def compare_stack_traces(self, trace1: str, trace2: str) -> float:
        """스택 트레이스 유사도 비교"""
        from difflib import SequenceMatcher
        
        # 기본 함수 호출 순서만 추출
        def extract_calls(trace: str) -> List[str]:
            calls = []
            for line in trace.split('\n'):
                if ' in ' in line:
                    func = line.split(' in ')[1].split()[0]
                    calls.append(func)
            return calls
        
        calls1 = extract_calls(trace1)
        calls2 = extract_calls(trace2)
        
        # 시퀀스 매칭으로 유사도 계산
        matcher = SequenceMatcher(None, calls1, calls2)
        return matcher.ratio()

    def generate_report(self):
        """최종 리포트 생성"""
        report_path = os.path.join(self.output_dir, "fuzzing_report.html")
        
        # 통계 수집
        stats = self.stats.copy()
        runtime = time.time() - stats['start_time']
        
        # 크래시 분석
        crash_analysis = []
        crashes_dir = os.path.join(self.output_dir, "crashes")
        for crash in os.listdir(crashes_dir):
            if not crash.startswith("id_"):
                continue
                
            crash_path = os.path.join(crashes_dir, crash)
            info_path = crash_path + ".txt"
            
            with open(info_path) as f:
                info = json.load(f)
            
            analysis_path = os.path.join(
                self.output_dir,
                "analysis",
                crash[3:19]  # id_ 제외한 해시값
            )
            
            if os.path.exists(analysis_path):
                with open(os.path.join(analysis_path, "stacktrace.txt")) as f:
                    stack_trace = f.read()
                
                with open(os.path.join(analysis_path, "similar_crashes.json")) as f:
                    similar = json.load(f)
                
                minimized = os.path.exists(os.path.join(analysis_path, "minimized"))
            else:
                stack_trace = "분석 정보 없음"
                similar = []
                minimized = False
            
            crash_analysis.append({
                'id': crash[3:19],
                'time': info['time'],
                'execution': info['execution'],
                'stack_trace': stack_trace,
                'similar_crashes': similar,
                'minimized': minimized
            })
        
        # 커버리지 분석
        coverage_stats = {
            'total_blocks': len(self.coverage_map),
            'covered_blocks': len([b for b in self.coverage_map.values() if b > 0]),
            'edge_hits': sum(self.coverage_map.values()),
            'unique_paths': stats['unique_paths']
        }
        
        # HTML 리포트 생성
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Fuzzing Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .section { margin: 20px 0; padding: 20px; border: 1px solid #ddd; }
                .crash { margin: 10px 0; padding: 10px; background: #f8f8f8; }
                .stats { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }
                .metric { padding: 10px; background: #eee; }
                pre { background: #f0f0f0; padding: 10px; overflow-x: auto; }
            </style>
        </head>
        <body>
            <h1>Fuzzing Report</h1>
            
            <div class="section">
                <h2>General Statistics</h2>
                <div class="stats">
                    <div class="metric">Run Time: {runtime:.2f} hours</div>
                    <div class="metric">Total Executions: {stats[total_execs]:,}</div>
                    <div class="metric">Executions/sec: {stats[total_execs]/runtime:.1f}</div>
                    <div class="metric">Unique Crashes: {stats[unique_crashes]}</div>
                    <div class="metric">Unique Paths: {stats[unique_paths]}</div>
                    <div class="metric">Last New Path: {stats[last_path]}</div>
                </div>
            </div>
            
            <div class="section">
                <h2>Coverage Analysis</h2>
                <div class="stats">
                    <div class="metric">Total Blocks: {coverage_stats[total_blocks]:,}</div>
                    <div class="metric">Covered Blocks: {coverage_stats[covered_blocks]:,}</div>
                    <div class="metric">Coverage Rate: {coverage_stats[covered_blocks]/coverage_stats[total_blocks]*100:.1f}%</div>
                    <div class="metric">Edge Hits: {coverage_stats[edge_hits]:,}</div>
                </div>
            </div>
            
            <div class="section">
                <h2>Crash Analysis</h2>
                {crash_details}
            </div>
        </body>
        </html>
        """
        
        # 크래시 세부정보 생성
        crash_details = []
        for crash in crash_analysis:
            crash_html = f"""
            <div class="crash">
                <h3>Crash {crash['id']}</h3>
                <p>발생 시간: {crash['time']}</p>
                <p>실행 번호: {crash['execution']:,}</p>
                <p>최소화됨: {'Yes' if crash['minimized'] else 'No'}</p>
                <h4>Stack Trace:</h4>
                <pre>{crash['stack_trace']}</pre>
                <h4>Similar Crashes:</h4>
                <ul>
                {''.join(f"<li>{s['hash']} (유사도: {s['similarity']:.2f})</li>" for s in crash['similar_crashes'])}
                </ul>
            </div>
            """
            crash_details.append(crash_html)
        
        # 최종 리포트 작성
        with open(report_path, 'w') as f:
            f.write(html_template.format(
                runtime=runtime/3600,  # 시간 단위로 변환
                stats=stats,
                coverage_stats=coverage_stats,
                crash_details='\n'.join(crash_details)
            ))
        
        self.logger.info(f"리포트 생성 완료: {report_path}")

    def plot_statistics(self):
        """통계 그래프 생성"""
        import matplotlib.pyplot as plt
        plt.style.use('seaborn')
        
        plots_dir = os.path.join(self.output_dir, "plots")
        
        # 실행 속도 그래프
        plt.figure(figsize=(10, 6))
        plt.plot(self.stats_history['times'], self.stats_history['execs_per_sec'])
        plt.title('Execution Speed Over Time')
        plt.xlabel('Time (hours)')
        plt.ylabel('Executions/sec')
        plt.savefig(os.path.join(plots_dir, 'speed.png'))
        plt.close()
        
        # 커버리지 그래프
        plt.figure(figsize=(10, 6))
        plt.plot(self.stats_history['times'], self.stats_history['coverage'])
        plt.title('Coverage Over Time')
        plt.xlabel('Time (hours)')
        plt.ylabel('Edge Coverage (%)')
        plt.savefig(os.path.join(plots_dir, 'coverage.png'))
        plt.close()
        
        # 크래시 발견 그래프
        plt.figure(figsize=(10, 6))
        crash_times = [c['time'] for c in self.crashes]
        plt.hist(crash_times, bins=50)
        plt.title('Crash Discovery Distribution')
        plt.xlabel('Time')
        plt.ylabel('Number of Crashes')
        plt.savefig(os.path.join(plots_dir, 'crashes.png'))
        plt.close()

def main():
    parser = argparse.ArgumentParser(description="Complete Production Fuzzer")
    parser.add_argument("binary", help="대상 바이너리 경로")
    parser.add_argument("--mode", choices=['file', 'network'], default='file',
                      help="퍼징 모드 선택")
    parser.add_argument("--input", required=True, help="시드 입력 디렉토리")
    parser.add_argument("--output", required=True, help="출력 디렉토리")
    parser.add_argument("--pin-tool", required=True, help="PIN 도구 경로")
    parser.add_argument("--cores", type=int, help="사용할 CPU 코어 수")
    parser.add_argument("--memory", type=int, help="메모리 제한 (MB)")
    parser.add_argument("--timeout", type=int, default=1,
                      help="실행 타임아웃 (초)")
    parser.add_argument("--dict", help="퍼징 사전 파일")
    parser.add_argument("--sync-dir", help="다른 퍼저와 동기화할 디렉토리")
    parser.add_argument("--afl-compat", action="store_true",
                      help="AFL 호환 모드 활성화")
    
    args = parser.parse_args()
    
    fuzzer = CompleteFuzzer(
        binary_path=args.binary,
        input_dir=args.input,
        output_dir=args.output,
        pin_tool=args.pin_tool,
        mode=args.mode,
        cores=args.cores,
        memory_limit=args.memory,
        timeout=args.timeout
    )
    
    if args.dict:
        fuzzer.load_dictionary(args.dict)
    
    if args.sync_dir:
        fuzzer.enable_sync(args.sync_dir)
    
    if args.afl_compat:
        fuzzer.enable_afl_compatibility()
    
    fuzzer.start_fuzzing()

if __name__ == "__main__":
    main()