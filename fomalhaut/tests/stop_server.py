# -*- coding: utf-8 -*-
# created by restran on 2017/05/28
from __future__ import unicode_literals, absolute_import

from fomalhaut.utils import to_unicode
import subprocess
import time


def kill_by_pid(pid):
    subprocess.Popen('kill -2 %s' % pid,
                     shell=True,
                     stdout=subprocess.PIPE)


def find_pid_and_kill(cmd):
    s = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    out_list = []
    for t in s.stdout:
        t = to_unicode(t)
        print(t)
        if 'grep' not in t:
            out_list.append(t)

    if len(out_list) > 0:
        line = out_list[0]
        print(line)
        pid = line.split(' ', 1)[0]
        kill_by_pid(pid)


def main():
    find_pid_and_kill('ps -A | grep fomalhaut.runserver')
    find_pid_and_kill('ps -A | grep fomalhaut.tests.api_server')
    print('wait server shutdown')
    time.sleep(3)


if __name__ == '__main__':
    main()
