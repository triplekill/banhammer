# core imports
import time
from os import system
from sys import argv
from collections import defaultdict
from subprocess import Popen, PIPE

# repeat timer
from RepeatTimer import RepeatTimer

whitelist = tuple()
banned = defaultdict(int)

def analyze(line):
    for w in whitelist:
        if w in line:
            return
    ip = line.split('-',1)[0]
    banned[ip] += 1
    if banned[ip] >= 20:
        system('ipfw table 2 add %s' % ip)
        system('''netstat -an | grep %s | awk '{print $4"."$5}' | awk -F '\.' '{print $1"."$2"."$3"."$4" "$5" "$6"."$7"."$8"."$9" "$10}' | while read line; do tcpdrop $line; done''' % ip)
        with open('banned.log', 'a') as f: f.write(time.ctime() + ' - %s\n' % ip)

if __name__ == '__main__':
    with open('whitelist.txt') as w:
        whitelist = w.read().splitlines()

RepeatTimer(5.0, lambda: banned.clear()).start()

log = argv[1]
print 'Now parsing %s' % log
p_tail = Popen('tail -f %s' % log, shell=True, stdout=PIPE)
while True:
    analyze(p_tail.stdout.readline())

