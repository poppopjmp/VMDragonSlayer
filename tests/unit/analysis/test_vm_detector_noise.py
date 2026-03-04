import os
import random

import pytest
from dragonslayer.analysis.vm_discovery.detector import VMDetector


def gen_noise_bytes(n: int, seed: int = 1234) -> bytes:
    rnd = random.Random(seed)
    return bytes(rnd.getrandbits(8) for _ in range(n))


@pytest.mark.parametrize("size", [256, 1024, 4096])
def test_noise_false_positive_rate(size: int):
    detector = VMDetector({"enable_caching": False, "confidence_threshold": 0.9})
    noise = gen_noise_bytes(size, seed=42)
    res = detector.detect_vm_structures(noise)
    assert res["confidence"] < 0.9
    assert res["vm_detected"] is False
