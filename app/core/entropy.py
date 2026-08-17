"""Shannon Entropy calculation module for file encryption detection."""
import math
from collections import Counter
from pathlib import Path
from typing import Union


def calculate_shannon_entropy(data: bytes) -> float:
    """
    Calculates Shannon entropy of raw bytes.
    Returns a float value between 0.0 (completely predictable) and 8.0 (completely random).
    """
    if not data:
        return 0.0

    length = len(data)
    byte_counts = Counter(data)
    entropy = 0.0

    for count in byte_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def calculate_file_entropy(
    file_path: Union[str, Path], sample_size: int = 65536
) -> float:
    """
    Reads the first sample_size bytes (default: 64 KB) of a file
    and calculates its Shannon entropy.
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return 0.0

    try:
        with open(path, "rb") as f:
            sample_bytes = f.read(sample_size)
        return calculate_shannon_entropy(sample_bytes)
    except (PermissionError, OSError):
        return 0.0