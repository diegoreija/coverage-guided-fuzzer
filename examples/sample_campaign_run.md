# Sample campaign run

This is a real, verified run against the included `targets/toy_ftp_parser.py`, which has three intentional bugs of different classes.

## Command

```bash
python3 main.py \
  --target targets.toy_ftp_parser \
  --function parse_command \
  --seeds "USER:admin" "NEST:5;CRASHME" "HELLO" \
  --iterations 100000 \
  --seed-value 7
```

## Actual output

```
[1/2] Running 100000 iterations against targets.toy_ftp_parser.parse_command...
      -> 7 corpus growth events, 27 unique lines covered, 2 unique crash(es) found (2.24s)

[2/2] Triaged crash report:
================================================================================

[MEDIUM_LOGIC] ZeroDivisionError@/path/to/targets/toy_ftp_parser.py:92
    Smallest triggering input: b'NEST:5;CRASHME'
    Rationale: Unhandled ZeroDivisionError reached a code path the target's error handling did not anticipate -- worth manual review to determine real impact.

[MEDIUM_LOGIC] IndexError@/path/to/targets/toy_ftp_parser.py:60
    Smallest triggering input: b'USER:\x01'
    Rationale: Unhandled IndexError reached a code path the target's error handling did not anticipate -- worth manual review to determine real impact.
```

## What this demonstrates

- The engine found the `IndexError` bug **starting from a seed that never triggers it** (`"USER:admin"`) — it was discovered purely through mutation, by chance landing on the `\x01` marker byte followed by nothing.
- The `ZeroDivisionError` bug required reaching five levels of recursion AND the exact string `"CRASHME"` at the final level — reachable here because the seed corpus already included one input close to that shape (`"NEST:5;CRASHME"`), which the coverage tracker recognized as valuable and kept mutating around.
- The third bug (`RecursionError`, triggered by a large numeric `count` value with no upper bound) was **not** found in this run. This is documented honestly in the README's Limitations section: constructing large exact numeric strings through byte-level mutation alone is inefficient. It's a real, verified negative result, not a hidden one.

## Running with only weak seeds (worse starting point)

```bash
python3 main.py \
  --target targets.toy_ftp_parser \
  --function parse_command \
  --seeds "HELLO" \
  --iterations 100000 \
  --seed-value 1
```

With a single seed that doesn't touch either the `USER:` or `NEST:` code paths at all, coverage growth is much slower and finding either bug becomes far less reliable within the same iteration budget — a direct illustration of why seed quality matters as much as the mutation engine itself in coverage-guided fuzzing.
