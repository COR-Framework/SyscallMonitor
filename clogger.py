__author__ = 'denis'

from cor.api import CORModule, Message
import subprocess
import threading
from cor.utils import adaptive_sleeper


def follow(thefile):
	thefile.seek(0, 2)
	sleeper = adaptive_sleeper(0.01, 1.5, 0.2)
	while True:
		line = thefile.readline()
		if not line:
			sleeper()
			continue
		sleeper(reset=True)
		yield line


def syscall_table():
	proc = str(subprocess.check_output(["ausyscall", "--dump"], universal_newlines=True))
	tdict = {}
	print("Evaluated")
	for row in proc.split("\n")[1:]:
		l, s, r = row.partition("	")
		tdict[l] = r
	return tdict


def lookup_syscall(number, table=syscall_table()):
	return table[number]


class Clogger(CORModule):

	def _add_rule(self, rule):
		subprocess.call("auditctl " + rule, shell=True)

	def add_rule(self, message):
		pass

	def readlog(self):
		with open(self.path, 'r') as fifo:
			for line in follow(fifo):
				tokens = line.split(" ")
				tdict = {}
				for token in tokens:
					l, s, r = token.partition("=")
					tdict[l] = r

				# rewrite syscall number to name
				if tdict["type"] == "SYSCALL":
					tdict["syscall"] = lookup_syscall(tdict["syscall"])

				msg = Message("SYSEVENT." + tdict.pop("type"), tdict)
				print(msg)
				self.messageout(msg)

	def __init__(self, path="/var/log/audit/audit.log", rules=[""], **kwargs):
		super().__init__(**kwargs)
		self.add_topics({"SYSEVENT.ADD_RULE": self.add_rule})
		self.path = path
		# delete all rules
		subprocess.call(["auditctl", "-D"])
		# wipe the log
		open(path, 'w').close()
		# add all rules
		for rule in rules:
			self._add_rule(rule)
		self.socket_thread = threading.Thread(target=self.readlog)
		self.socket_thread.start()
