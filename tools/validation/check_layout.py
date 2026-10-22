#!/usr/bin/env python3
"""Read-only validation of local includes and runtime module paths after relocation."""
import json
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parents[2]
missing_includes = []
missing_modules = []
includes = 0
modules = 0
for folder in ('compiler', 'tests'):
    for path in (root / folder).rglob('*'):
        if path.suffix not in ('.c', '.h') or not path.is_file():
            continue
        text = path.read_text(encoding='utf-8')
        for target in re.findall(r'^\s*#\s*include\s*"([^"\n]+)"', text, re.M):
            includes += 1
            resolved = (path.parent / target).resolve()
            if not resolved.is_relative_to(root) or not resolved.is_file():
                missing_includes.append({'file': str(path.relative_to(root)), 'include': target})
        if folder == 'compiler':
            for target in re.findall(r'"(compiler/[^"\n]+\.nova)"', text):
                modules += 1
                if not (root / target).is_file():
                    missing_modules.append({'file': str(path.relative_to(root)), 'module': target})
result = {'includes_checked': includes, 'module_paths_checked': modules,
          'missing_includes': missing_includes, 'missing_modules': missing_modules,
          'obsolete_toolchain_directory': (root / 'toolchain').exists(),
          'os_in_examples': (root / 'examples/os').is_dir(),
          'os_in_legacy': (root / 'legacy/os').exists()}
result['ok'] = not (missing_includes or missing_modules or result['obsolete_toolchain_directory'] or result['os_in_legacy']) and result['os_in_examples']
print(json.dumps(result, indent=2))
sys.exit(0 if result['ok'] else 1)
