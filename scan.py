#!/usr/bin/python

import re
import sys
import socket
import requests
import dns.resolver
from time import time
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing.dummy import Lock

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

DNSServer = [['114.114.114.114'], ['8.8.8.8'],
		             ['223.6.6.6'], ['223.5.5.5'], ['119.29.29.29'],
		             ['180.76.76.76'], ['1.2.4.8'], ['208.67.222.222']]

class Scanner(object):
	def __init__(self, target, startPort, endPort):
		self.target = target
		self.startPort = startPort
		self.endPort = endPort

		self.dnsRecords = []
		self.mutex = Lock()

		self.ports = []
		self.getPorts()
		self.time = time()

	def getPorts(self):
		for i in range(int(self.startPort), int(self.endPort) + 1):
			self.ports.append(i)

	def checkCdn(self):
		myResolver = dns.resolver.Resolver()
		myResolver.lifetime = myResolver.timeout = 2.0
		
		try:
			for i in DNSServer:
				myResolver.nameservers = i
				record = myResolver.query(self.target)
				self.dnsRecords.append(record[0].address)
			self.dnsRecords = list(set(self.dnsRecords))
		except Exception as e:
			pass
		finally:
			return True if len(self.dnsRecords) > 1 else False

	def scanPort(self, port):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(0.2)
			return True if s.connect_ex((self.target, port)) == 0 else False
		except Exception as e:
			pass
		finally:
			s.close()

	def getHttpBanner(self, url):
		try:
			r = requests.get(
			  url,
			  headers={'UserAgent': UserAgent().random},
			  timeout=2,
			  verify=False,
			  allow_redirects=True)
			soup = BeautifulSoup(r.content, 'lxml')
			return soup.title.text.strip('\n').strip()
		except Exception as e:
			pass

	def getSocketInfo(self, port):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.settimeout(0.2)
			s.connect((self.target, port))
			s.send('HELLO\r\n')
			return s.recv(1024).split('\r\n')[0].strip('\r\n')
		except Exception as e:
			pass
		finally:
			s.close()

	def run(self, port):
		try:
			if self.scanPort(port):
				banner = self.getHttpBanner(f'http://{self.target}:{port}')
				self.mutex.acquire()
				if banner:
					print(f'{str(port).rjust(6)} ---- open   {banner[:18]}')
				else:
					banner = self.getHttpBanner(f'https://{self.target}:{port}')
					if banner:
						print(f'{str(port).rjust(6)} ---- open   {banner[:18]}')
					else:
						banner = self.getSocketInfo(port)
						if banner:
							print(f'{str(port).rjust(6)} ---- open   {banner[:18]}')
						else:
							print(f'{str(port).rjust(6)} ---- open ')
				self.mutex.release()
		except Exception as e:
			pass

	def _start(self):
		try:
			print(f'Endereço de digitalização: {socket.gethostbyname(self.target)}\n')

			pool = ThreadPool(processes=100)
			pool.map_async(self.run, self.ports).get(0xffff)

			pool.close()
			pool.join()

			print(f'Demorado para completar a verificação: {time() - self.time} 秒.\n')
		except Exception as e:
			print(e)
		except KeyboardInterrupt:
			print('O usuário encerrou a varredura ...')
			sys.exit(1)

	def scanRecords(self):

		inputNums = input('\nPor favor, digite o número de série a ser verificado \nInsira 0 para todas as varreduras, se você não inserir, cancela a varredura \nAo escanear uma porta específica, digite o número de série na frente da porta, e cada número de série é separados por um espaço \nPor favor, digite:').strip()

		if inputNums == '':
			print('O usuário encerrou a varredura ...')
			sys.exit(1)

		if inputNums == '0':
			for (i, ip) in enumerate(self.dnsRecords):
				print(f'\nPrimeiro{i+1}个 IP Comece a escanear...')
				Scanner(ip, sys.argv[2], sys.argv[3]).checkTarget()
		else:
			recordsLen = len(self.dnsRecords)
			nums = inputNums.split(sep=' ')

			if len(nums) < 1:
				print('O usuário encerra a varredura...')
				sys.exit(1)

			for (i, num) in enumerate(nums):
				num = int(num)
				print(f'\nPrimeiro{i+1}个 IP Comece a escanear...')
				if num > recordsLen:
					print('Número de série inserido ilegal...')
					continue

				Scanner(self.dnsRecords[num - 1], sys.argv[2],
				  sys.argv[3]).checkTarget()

	def checkTarget(self):

		ipRegex = re.compile(
		  '^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')

		if ipRegex.match(self.target):
			self._start()
		elif not self.checkCdn():
			print('O nome de domínio não tem registro de resolução DNS ...')
			sys.exit(1)
		else:
			print('O IP para resolução de nome de domínio é o seguinte:')

			for (i, ip) in enumerate(self.dnsRecords):
				print(str(i+1) + ' : ' + ip)

			self.scanRecords()

if __name__ == '__main__':
	print('\nA varredura da porta começa ...\n')

	if len(sys.argv) != 4:
		print(f'usage: python {sys.argv[0]} ip/domain startPort endPort')
		sys.exit(0)

	Scanner(sys.argv[1], sys.argv[2], sys.argv[3]).checkTarget()