#!/usr/bin/env python3
# converts obfuscated BPFDoor controller's source to human readable
# @haxrob 2026-03-27

import subprocess
import re

with open('2eacc8d91b9829b9606a7945fc5311fb5876cfb42ffccc1b91f61841237b04c1', 'r') as f:
    code = f.read()

strings = []
def save_string(m):
    s = m.group(0)
    s = s.replace('\\.', '')
    strings.append(s)
    return f'\x00STR{len(strings)-1}\x00'

code = re.sub(r'"(?:[^"\\]|\\.)*"', save_string, code)

code = code.replace('.\n', '\n')
code = code.replace(';.', ';\n')
code = code.replace('}.', '}\n')
code = re.sub(r'(#endif|#ifndef \w+)\.', r'\1\n', code)
code = re.sub(r'\.(?![a-zA-Z0-9])', '\n', code)
code = re.sub(r'^(\s*)\.', r'\1', code, flags=re.MULTILINE)

for i, s in enumerate(strings):
    code = code.replace(f'\x00STR{i}\x00', s)

with open('bpfdoor_controller_fixed.c', 'w') as f:
    f.write(code)

print('Formatted output written to bfpdoor_controller_fixed.c')
