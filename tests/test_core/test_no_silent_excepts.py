import os
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]


def test_no_silent_except_blocks():
    errors = []
    for path in sorted(ROOT.rglob('*.py')):
        if any(part.startswith('.') for part in path.parts):
            continue
        if 'tests' in path.parts:
            continue
        if 'venv' in path.parts or '__pycache__' in path.parts:
            continue

        text = path.read_text(encoding='utf-8', errors='ignore')
        lines = text.splitlines()
        for index, line in enumerate(lines, start=1):
            stripped = line.strip()
            if re.match(r'^except\s*:\s*$', stripped):
                errors.append(f'{path}:{index}: bare except')
            elif re.match(r'^except\s+Exception(?:\s+as\s+\w+)?\s*:\s*$', stripped):
                # If the immediately following non-empty code line is a pass/continue, it's a silent recovery path.
                next_index = index
                while next_index < len(lines):
                    next_index += 1
                    next_line = lines[next_index - 1].strip()
                    if not next_line or next_line.startswith('#'):  # skip blank lines and comments
                        continue
                    if next_line in {'pass', 'continue'}:
                        errors.append(f'{path}:{index}: except Exception with silent {next_line}')
                    break
    assert not errors, '\n'.join(errors)
