#!/usr/bin/env python3

import logging
import sh

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('r')
logger.setLevel(logging.DEBUG)

vulnfiles = [
    {'type': 'image', 'val': 'alpine:3'},
    {'type': 'image', 'val': 'ubuntu:20.04'},
    {'type': 'image', 'val': 'alpine:edge'},
    {'type': 'image', 'val': 'nginx:1.21-alpine', 'not_pull': False},
    {'type': 'image', 'val': 'golang:latest'},
    {'type': 'image', 'val': 'golang:1-alpine'},
    {'type': 'image', 'val': 'python:3'},
    {'type': 'image', 'val': 'gcr.io/distroless/static-debian11',
        'report': 'distroless-static'},
    {'type': 'image', 'val': 'gcr.io/distroless/base-debian11',
        'report': 'distroless-base'},
    {'type': 'image', 'val': 'gcr.io/distroless/java11-debian11',
        'report': 'distroless-java11'},
    {'type': 'image', 'val': 'gcr.io/distroless/cc-debian11',
        'report': 'distroless-cc'},
    {'type': 'image', 'val': 'gcr.io/gcr.io/distroless/nodejs-debian11',
        'report': 'distroless-nodejs'},
    {'type': 'image', 'val': 'gcr.io/distroless/python3-debian11',
        'report': 'distroless-python3'},
]


def process_output(line):
    print(line, sep='', end='')


if '__main__' == __name__:

    for one in vulnfiles:
        logger.info("scanning %s", one)
        _type = one['type']
        _val = one['val']
        report_name = one.get('report', '') or _val
        if _type == 'image' and not one.get('not_pull', False):
            logger.info("pull %s", _val)
            sh.docker('pull', _val)
        sh.trivy(_type, '--severity', 'CRITICAL,HIGH',
                 _val, _out=f'report/{report_name}.txt')
