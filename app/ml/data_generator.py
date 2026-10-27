"""
Synthetic dataset generator for normal and suspicious security events.
Clearly labels all generated records as synthetic.
Used for model training demonstration and seeding the demo database.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

import numpy as np

RANDOM_SEED = 42
rng = np.random.default_rng(RANDOM_SEED)
random.seed(RANDOM_SEED)

ATTACK_CATEGORIES = [
    "brute_force",
    "credential_stuffing",
    "port_scan",
    "anomalous_traffic",
]

SAMPLE_IPS = [
    "192.168.1." + str(i) for i in range(1, 20)
] + [
    "10.0.0." + str(i) for i in range(1, 10)
] + [
    "203.0.113." + str(i) for i in range(1, 15)   # TEST-NET-3 (RFC 5737)
]

SAMPLE_USERS = [f"user_{i:03d}" for i in range(1, 30)] + ["admin", "root", "svc_account", "jenkins"]


def _random_timestamp(base: datetime, spread_hours: int = 72) -> datetime:
    offset = timedelta(seconds=int(rng.uniform(0, spread_hours * 3600)))
    return base - offset


def generate_normal_event(base_time: datetime) -> Dict[str, Any]:
    hour = int(rng.integers(8, 18))  # business hours
    ts = _random_timestamp(base_time, 72)
    ts = ts.replace(hour=hour, tzinfo=timezone.utc)
    return {
        "timestamp": ts,
        "user_identifier": random.choice(SAMPLE_USERS[:20]),
        "source_ip": random.choice(SAMPLE_IPS[:15]),
        "login_result": rng.choice(["success", "failure"], p=[0.92, 0.08]),
        "event_type": "auth",
        "failed_attempts_window": int(rng.integers(0, 2)),
        "distinct_accounts_targeted": 1,
        "request_frequency": float(rng.uniform(0.1, 2.0)),
        "hour_of_day": hour,
        "geo_country": "IN",
        "duration": float(rng.uniform(0.1, 30.0)),
        "bytes_sent": float(rng.uniform(100, 5000)),
        "bytes_received": float(rng.uniform(200, 10000)),
        "packets": int(rng.integers(5, 200)),
        "protocol": "TCP",
        "destination_port": int(rng.choice([80, 443, 8080, 22, 3306])),
        "is_synthetic": True,
        "source": "generated",
        "attack_label": "normal",
    }


def generate_brute_force_event(base_time: datetime) -> Dict[str, Any]:
    hour = int(rng.integers(0, 24))
    ts = _random_timestamp(base_time, 24)
    ts = ts.replace(hour=hour, tzinfo=timezone.utc)
    return {
        "timestamp": ts,
        "user_identifier": random.choice(SAMPLE_USERS),
        "source_ip": random.choice(SAMPLE_IPS[15:]),
        "login_result": rng.choice(["failure", "lockout"], p=[0.9, 0.1]),
        "event_type": "auth",
        "failed_attempts_window": int(rng.integers(10, 80)),
        "distinct_accounts_targeted": int(rng.integers(1, 3)),
        "request_frequency": float(rng.uniform(15, 60)),
        "hour_of_day": hour,
        "geo_country": rng.choice(["??", "CN", "RU", "US", None]),
        "duration": float(rng.uniform(0.01, 0.5)),
        "bytes_sent": float(rng.uniform(50, 500)),
        "bytes_received": float(rng.uniform(20, 200)),
        "packets": int(rng.integers(5, 50)),
        "protocol": "TCP",
        "destination_port": 22,
        "is_synthetic": True,
        "source": "generated",
        "attack_label": "brute_force",
    }


def generate_credential_stuffing_event(base_time: datetime) -> Dict[str, Any]:
    hour = int(rng.integers(0, 24))
    ts = _random_timestamp(base_time, 24)
    ts = ts.replace(hour=hour, tzinfo=timezone.utc)
    return {
        "timestamp": ts,
        "user_identifier": random.choice(SAMPLE_USERS),
        "source_ip": random.choice(SAMPLE_IPS),
        "login_result": rng.choice(["failure", "success"], p=[0.85, 0.15]),
        "event_type": "auth",
        "failed_attempts_window": int(rng.integers(3, 15)),
        "distinct_accounts_targeted": int(rng.integers(5, 30)),
        "request_frequency": float(rng.uniform(5, 25)),
        "hour_of_day": hour,
        "geo_country": rng.choice(["??", "BR", "VN", None]),
        "duration": float(rng.uniform(0.05, 1.0)),
        "bytes_sent": float(rng.uniform(100, 1000)),
        "bytes_received": float(rng.uniform(50, 500)),
        "packets": int(rng.integers(10, 80)),
        "protocol": "TCP",
        "destination_port": 443,
        "is_synthetic": True,
        "source": "generated",
        "attack_label": "credential_stuffing",
    }


def generate_port_scan_event(base_time: datetime) -> Dict[str, Any]:
    hour = int(rng.integers(0, 24))
    ts = _random_timestamp(base_time, 12)
    ts = ts.replace(hour=hour, tzinfo=timezone.utc)
    return {
        "timestamp": ts,
        "user_identifier": None,
        "source_ip": random.choice(SAMPLE_IPS[15:]),
        "login_result": None,
        "event_type": "network",
        "failed_attempts_window": 0,
        "distinct_accounts_targeted": 0,
        "request_frequency": float(rng.uniform(50, 300)),
        "hour_of_day": hour,
        "geo_country": None,
        "duration": float(rng.uniform(0.001, 0.1)),
        "bytes_sent": float(rng.uniform(40, 200)),
        "bytes_received": float(rng.uniform(0, 100)),
        "packets": int(rng.integers(1, 20)),
        "protocol": rng.choice(["TCP", "UDP", "ICMP"]),
        "destination_port": int(rng.integers(1, 65535)),
        "is_synthetic": True,
        "source": "generated",
        "attack_label": "port_scan",
    }


def generate_anomalous_traffic_event(base_time: datetime) -> Dict[str, Any]:
    hour = int(rng.integers(0, 6))
    ts = _random_timestamp(base_time, 6)
    ts = ts.replace(hour=hour, tzinfo=timezone.utc)
    return {
        "timestamp": ts,
        "user_identifier": random.choice(SAMPLE_USERS[-5:]),
        "source_ip": random.choice(SAMPLE_IPS),
        "login_result": "success",
        "event_type": "network",
        "failed_attempts_window": 0,
        "distinct_accounts_targeted": 1,
        "request_frequency": float(rng.uniform(100, 500)),
        "hour_of_day": hour,
        "geo_country": None,
        "duration": float(rng.uniform(300, 3600)),
        "bytes_sent": float(rng.uniform(1_000_000, 50_000_000)),
        "bytes_received": float(rng.uniform(1000, 50000)),
        "packets": int(rng.integers(1000, 50000)),
        "protocol": "TCP",
        "destination_port": int(rng.choice([443, 8443, 9200, 27017])),
        "is_synthetic": True,
        "source": "generated",
        "attack_label": "anomalous_traffic",
    }


def generate_dataset(
    n_normal: int = 500,
    n_per_attack: int = 50,
    base_time: datetime | None = None,
) -> List[Dict[str, Any]]:
    """
    Generate a synthetic dataset with normal and attack events.
    All records are marked is_synthetic=True.
    Returns list of event dicts including attack_label for supervised training.
    """
    if base_time is None:
        base_time = datetime.now(timezone.utc)

    records: List[Dict[str, Any]] = []

    for _ in range(n_normal):
        records.append(generate_normal_event(base_time))

    generators = [
        generate_brute_force_event,
        generate_credential_stuffing_event,
        generate_port_scan_event,
        generate_anomalous_traffic_event,
    ]
    for gen_fn in generators:
        for _ in range(n_per_attack):
            records.append(gen_fn(base_time))

    # Shuffle
    random.shuffle(records)
    return records
