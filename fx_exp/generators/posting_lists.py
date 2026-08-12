import random


def generate_posting_lists(u, distribution, seed, fixed_length=1):
    rng = random.Random(seed)
    lengths = []
    if distribution.startswith("fixed"):
        if ":" in distribution:
            fixed_length = int(distribution.split(":", 1)[1])
        lengths = [fixed_length] * u
    elif distribution == "uniform":
        lengths = [rng.randint(1, 8) for _ in range(u)]
    elif distribution == "zipf":
        # Bounded deterministic long tail; no numpy dependency is required.
        lengths = [max(1, min(64, int(u / (rank + 1)))) for rank in range(u)]
        rng.shuffle(lengths)
    elif distribution == "heavy-repeat":
        lengths = [max(1, u // 2) if index < max(1, u // 16) else 1 for index in range(u)]
    else:
        raise ValueError("unknown posting distribution: {0}".format(distribution))
    postings, row = [], 1
    for length in lengths:
        postings.append(list(range(row, row + length)))
        row += length
    return postings
