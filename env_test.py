#!/usr/bin/env python3

import os

print('in env_test.py')
print(os.environ['GIT_DIFF'])

for k,v in os.environ.items():
    print(f"{k} {v}")

'''
os.getenv('GITHUB_REPOSITORY')
'''
