"""
test_fp_and_crossval.py
Cross-validation + Empirical FP rate measurement

1. Hash cross-validation: compares Python hash output against C++ ground truth
2. Empirical FP rate: measures actual vs theoretical at multiple saturation levels
3. Merge commutativity: verifies A|B == B|A for random inputs

Run: python3 test_fp_and_crossval.py  (after compiling and running the C++ counterpart)
"""

import subprocess
import sys
import os
import math

# ---------------------------------------------------------------------------
# Import ghost_meadow.py from same directory
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ghost_meadow import GhostMeadow

KEY = 0xDEADBEEFCAFEBABE
passed = 0
failed = 0


def check(name, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  PASS: {name}")
        passed += 1
    else:
        print(f"  FAIL: {name} {detail}")
        failed += 1


# ---------------------------------------------------------------------------
# PHASE 1: Hash cross-validation against C++ ground truth
# ---------------------------------------------------------------------------
def run_hash_crossval():
    global passed, failed
    print("=" * 60)
    print("PHASE 1: HASH CROSS-VALIDATION (C++ <-> Python)")
    print("=" * 60)

    # Compile and run C++ ground truth
    cpp_src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "test_hash_crossval.cpp")
    cpp_bin = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "test_hash_crossval")

    print("  Compiling C++ ground truth...")
    rc = subprocess.call(
        ["g++", "-std=c++11", "-O2", "-o", cpp_bin, cpp_src],
        cwd=os.path.dirname(os.path.abspath(__file__))
    )
    if rc != 0:
        print("  FAIL: C++ compilation failed")
        failed += 1
        return

    print("  Running C++ ground truth...")
    result = subprocess.run([cpp_bin], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  FAIL: C++ execution failed: {result.stderr}")
        failed += 1
        return

    cpp_output = result.stdout.strip().split("\n")

    # Replicate the Python _hash to get raw hash (before % m)
    def py_hash_raw(mission_key, data, hash_idx):
        FNV_PRIME = 16777619
        FNV_OFFSET = 2166136261
        seed = (mission_key ^ (hash_idx * 0x9E3779B97F4A7C15)) & 0xFFFFFFFF
        h = (FNV_OFFSET ^ seed) & 0xFFFFFFFF
        for b in data:
            h = ((h ^ b) * FNV_PRIME) & 0xFFFFFFFF
        h = ((h ^ (h >> 16)) * 0x45D9F3B) & 0xFFFFFFFF
        h = h ^ (h >> 16)
        return h

    # Test vectors (must match C++)
    vectors = {
        "3byte_A": bytes([0x01, 0x02, 0x03]),
        "3byte_B": bytes([0xAA, 0xBB, 0xCC]),
        "1byte":   bytes([0xFF]),
        "4byte":   bytes([0xDE, 0xAD, 0xBE, 0xEF]),
        "8byte":   bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]),
        "zeros":   bytes([0x00, 0x00, 0x00, 0x00]),
        "ones":    bytes([0xFF, 0xFF, 0xFF, 0xFF]),
        "single_0": bytes([0x00]),
    }

    # Parse C++ output and compare
    hash_mismatches = 0
    hash_total = 0
    bit_array_cpp = None
    cpp_set_bits = None
    cpp_fp_data = []

    for line in cpp_output:
        if line.startswith("#") or line.strip() == "":
            continue

        if line.startswith("BITS "):
            bit_array_cpp = line.split()[1]
            continue
        if line.startswith("SATURATION "):
            continue
        if line.startswith("BITS_SET ") or line.startswith("SET_BITS "):
            if line.startswith("SET_BITS "):
                cpp_set_bits = int(line.split()[1])
            continue

        parts = line.strip().split()
        if len(parts) == 5 and parts[0].isdigit():
            m_val = int(parts[0])
            hash_idx = int(parts[1])
            label = parts[2]
            cpp_raw_hash = int(parts[3])
            cpp_bit_pos = int(parts[4])

            if label not in vectors:
                continue

            data = vectors[label]
            py_raw = py_hash_raw(KEY, data, hash_idx)
            py_bit_pos = py_raw % m_val

            hash_total += 1
            if py_raw != cpp_raw_hash:
                hash_mismatches += 1
                print(f"  MISMATCH: m={m_val} k={hash_idx} {label}: "
                      f"C++ raw={cpp_raw_hash}, Python raw={py_raw}")
            elif py_bit_pos != cpp_bit_pos:
                hash_mismatches += 1
                print(f"  MISMATCH: m={m_val} k={hash_idx} {label}: "
                      f"C++ pos={cpp_bit_pos}, Python pos={py_bit_pos}")

        # Parse FP rate data
        if len(parts) == 4 and not parts[0].startswith("#"):
            try:
                n_seeded = int(parts[0])
                sat_pct = float(parts[1])
                emp_fp = float(parts[2])
                theo_fp = float(parts[3])
                cpp_fp_data.append((n_seeded, sat_pct, emp_fp, theo_fp))
            except ValueError:
                pass

    check(f"Hash raw values match ({hash_total} vectors)",
          hash_mismatches == 0 and hash_total > 0,
          f"{hash_mismatches}/{hash_total} mismatches")

    # Bit-array level check: seed same observations in Python, compare hex
    if bit_array_cpp:
        py_meadow = GhostMeadow(KEY, 0, m=1024, k=3)
        py_meadow.seed(bytes([0x01, 0x02, 0x03]))
        py_meadow.seed(bytes([0xAA, 0xBB, 0xCC]))

        py_hex = "".join(f"{b:02x}" for b in py_meadow.raw_bits())
        check("Bit arrays match after identical seeds",
              py_hex == bit_array_cpp,
              f"\n    C++: {bit_array_cpp[:80]}...\n    Py:  {py_hex[:80]}...")

        py_set = sum(bin(b).count('1') for b in py_meadow.raw_bits())
        if cpp_set_bits is not None:
            check(f"Set bit count matches (C++={cpp_set_bits}, Py={py_set})",
                  py_set == cpp_set_bits)

    # Report C++ FP data for reference
    if cpp_fp_data:
        print("\n  C++ FP rate results (for reference):")
        print("  n_seeded  sat%     empirical   theoretical")
        for n, s, e, t in cpp_fp_data:
            ratio = e / t if t > 0 else 0
            print(f"  {n:>7d}  {s:>6.2f}%  {e:>10.6f}  {t:>10.6f}  (ratio={ratio:.2f})")


# ---------------------------------------------------------------------------
# PHASE 2: Empirical FP rate (Python-side)
# ---------------------------------------------------------------------------
def run_fp_rate():
    print("\n" + "=" * 60)
    print("PHASE 2: EMPIRICAL FALSE POSITIVE RATE (Python)")
    print("=" * 60)

    # Use m=4096, k=2 (Python default) — this is the sizing we actually ship
    m = 4096
    k = 2
    n_queries = 10000
    test_counts = [50, 200, 500, 1000, 1500]

    print(f"  Config: m={m}, k={k}, queries={n_queries}")
    print(f"  {'n_seeded':>8s}  {'sat%':>7s}  {'empirical':>10s}  {'theoretical':>12s}  {'ratio':>6s}  {'status':>6s}")

    all_ok = True
    for n_seed in test_counts:
        meadow = GhostMeadow(KEY, 0, m=m, k=k)

        # Seed n observations
        for i in range(n_seed):
            obs = bytes([i & 0xFF, (i >> 8) & 0xFF, 0xAA, 0xAA])
            meadow.seed(obs)

        sat = meadow.saturation()

        # Query never-seeded observations
        fp_count = 0
        for i in range(n_queries):
            qobs = bytes([i & 0xFF, (i >> 8) & 0xFF, 0xBB, 0xBB])
            if meadow.query(qobs):
                fp_count += 1

        empirical = fp_count / n_queries
        # Theoretical: (1 - e^(-kn/m))^k
        theoretical = (1.0 - math.exp(-k * n_seed / m)) ** k

        ratio = empirical / theoretical if theoretical > 0 else 0
        # Allow 3x deviation — hash bias can shift things, but not by 10x
        ok = ratio < 3.0 or empirical < 0.01
        status = "OK" if ok else "HIGH"
        if not ok:
            all_ok = False

        print(f"  {n_seed:>8d}  {sat*100:>6.2f}%  {empirical:>10.6f}  {theoretical:>12.6f}  {ratio:>5.2f}x  {status:>6s}")

    check("FP rate within 3x of theoretical across all saturation levels", all_ok)

    # Verify zero false negatives
    print("\n  Verifying zero false negatives...")
    meadow = GhostMeadow(KEY, 0, m=4096, k=2)
    fn_count = 0
    n_fn_test = 1000
    for i in range(n_fn_test):
        obs = bytes([i & 0xFF, (i >> 8) & 0xFF, 0xCC, 0xCC])
        meadow.seed(obs)

    for i in range(n_fn_test):
        obs = bytes([i & 0xFF, (i >> 8) & 0xFF, 0xCC, 0xCC])
        if not meadow.query(obs):
            fn_count += 1

    check(f"Zero false negatives ({n_fn_test} seeded, {fn_count} missed)", fn_count == 0)


# ---------------------------------------------------------------------------
# PHASE 3: Merge commutativity / associativity
# ---------------------------------------------------------------------------
def run_merge_properties():
    print("\n" + "=" * 60)
    print("PHASE 3: MERGE COMMUTATIVITY & ASSOCIATIVITY")
    print("=" * 60)

    # Commutativity: A|B == B|A
    a = GhostMeadow(KEY, 0, m=1024, k=3)
    b = GhostMeadow(KEY, 1, m=1024, k=3)

    for i in range(50):
        a.seed(bytes([i & 0xFF, 0xAA]))
    for i in range(50):
        b.seed(bytes([i & 0xFF, 0xBB]))

    # A|B
    ab = GhostMeadow(KEY, 10, m=1024, k=3)
    for i in range(50):
        ab.seed(bytes([i & 0xFF, 0xAA]))
    ab.merge_raw(b.raw_bits(), 1)

    # B|A
    ba = GhostMeadow(KEY, 11, m=1024, k=3)
    for i in range(50):
        ba.seed(bytes([i & 0xFF, 0xBB]))
    ba.merge_raw(a.raw_bits(), 0)

    check("Merge commutativity (A|B == B|A)",
          ab.raw_bits() == ba.raw_bits())

    # Associativity: (A|B)|C == A|(B|C)
    c = GhostMeadow(KEY, 2, m=1024, k=3)
    for i in range(50):
        c.seed(bytes([i & 0xFF, 0xCC]))

    # (A|B)|C
    abc1 = GhostMeadow(KEY, 20, m=1024, k=3)
    for i in range(50):
        abc1.seed(bytes([i & 0xFF, 0xAA]))
    abc1.merge_raw(b.raw_bits(), 1)
    abc1.merge_raw(c.raw_bits(), 2)

    # A|(B|C)
    bc = GhostMeadow(KEY, 21, m=1024, k=3)
    for i in range(50):
        bc.seed(bytes([i & 0xFF, 0xBB]))
    bc.merge_raw(c.raw_bits(), 2)

    abc2 = GhostMeadow(KEY, 22, m=1024, k=3)
    for i in range(50):
        abc2.seed(bytes([i & 0xFF, 0xAA]))
    abc2.merge_raw(bc.raw_bits(), 21)

    check("Merge associativity ((A|B)|C == A|(B|C))",
          abc1.raw_bits() == abc2.raw_bits())

    # Idempotency: A|A == A
    a_copy_bits = bytearray(a.raw_bits())
    a_before = bytearray(a.raw_bits())
    a.merge_raw(a_copy_bits, 0)
    check("Merge idempotency (A|A == A)",
          a.raw_bits() == a_before)


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    run_hash_crossval()
    run_fp_rate()
    run_merge_properties()

    print("\n" + "=" * 60)
    total = passed + failed
    print(f"RESULTS: {passed}/{total} passed, {failed} failed")
    if failed == 0:
        print("ALL TESTS PASSED")
    else:
        print("FAILURES DETECTED")
    print("=" * 60)
    sys.exit(0 if failed == 0 else 1)
