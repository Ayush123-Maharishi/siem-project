"""generate_logs.py - Log generator entry point (backward-compatible)."""
from collectors import generator

LOG_FILE = generator.LOG_FILE


def generate(seed=42):
    return generator.generate(seed=seed)


if __name__ == "__main__":
    count = generate()
    print(f"[+] Generated {count} log events -> {LOG_FILE}")
