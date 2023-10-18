import json
from urllib.parse import urlparse
import requests
import urllib3
import sys
from bs4 import BeautifulSoup
import argparse
import time
from colorama import init,Fore,Back,Style


st = time.time()

#initialize colorama, necessary for windows environment
init()

# Disable SSL insecure warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Timeout for all HTTP requests
GLOBAL_HTTP_TIMEOUT = 3

def banner():
	  print(Fore.CYAN + """
  #####    #####    #####   ######    #####  
 ##   ##  ##   ##  ##   ##  # ## #   ##   ## 
 #        ##   ##  #          ##     ##   ## 
  #####   ##   ##   #####     ##     ##   ## 
      ##  ##   ##       ##    ##     ##   ## 
 ##   ##  ##   ##  ##   ##    ##     ##   ## 
  #####    #####    #####    ####     ##### 
  """ + Fore.RESET)


def normalize_url(domain, src):
	'''
	(Try to) Normalize URL to its absolute form
	'''
	src = src.strip()
	src = src.rstrip('/')

	# Protocol relative URL
	if src.startswith('//'):
		return 'http:{}'.format(src)
	
	# Relative URL with /
	if src.startswith('/'):
		return 'http://{}{}'.format(domain, src)

	# Relative URL with ?
	if src.startswith('?'):
		return 'http://{}/{}'.format(domain, src)

	# Relative URL with ./
	if src.startswith('./'):
		return 'http://{}{}'.format(domain, src[1:])

	# Absolute URL
	if src.startswith('https://') or src.startswith('http://'):
		return src

	# Else let's hope it is relative URL
	return 'http://{}/{}'.format(domain, src)

def extract_javascript(domain, source_code):
	'''
	Extract and normalize external javascript files from HTML
	'''

	tree = BeautifulSoup(source_code, 'lxml')
	scripts = [normalize_url(domain, s.get('src')) for s in tree.find_all('script') if s.get('src')]
	return list(set(scripts))

def extract_links(domain, source_code):
	'''
	Extract and normalize links in HTML file 
	'''

	tree = BeautifulSoup(source_code, 'lxml')
	hrefs = [normalize_url(domain, s.get('href')) for s in tree.find_all('a') if s.get('href')]
	return list(set(hrefs))

def extract_styles(domain, source_code):
	'''
	Extract and normalize CSS in HTML file 
	'''

	tree = BeautifulSoup(source_code, 'lxml')
	hrefs = [normalize_url(domain, s.get('href')) for s in tree.find_all('link') if s.get('href')]
	return list(set(hrefs))

def save_to_file(input_list,output_file_name):
	if input_list:
		with open(output_file_name,"w") as f:
			for item in input_list:
				f.write(f'{item}\n')
	else:
		pass

def list_len(lst):
	'''
	find the lenght of objects in a nested list
	'''
	if 'list' in str(type(lst)):
		lst_len = [len(x) for x in lst]
	else:
		lst_len = lst
	return sum(lst_len)

def save_scraped_urls(in_urls_lst,out_urls_file):
	'''
	save all scraped urls in the initial stage to a file
	'''
	with open(out_urls_file,'w') as f:
		for domain in in_urls_lst:
			for url in domain:
				f.write(f'{url}\n')

def get_2nd_order_domains(input_domains_file,scraped_urls_file):
	'''get 2nd order domains from urls excluding excluding 1st order domains 
	e.g arguments be like ("input_domains.txt","scraped_urls.txt")
	'''
	input_domains = file_to_list(input_domains_file)
	_2nd_order_domains = []
	dic, output_domains = urls_to_domains_dict(scraped_urls_file) # returns a dictionary of urls:domains and a set of domains
	for domain in output_domains:
		if domain not in input_domains and domain != "":
			_2nd_order_domains.append(domain)
	# _2nd_order_domains_v2 = [domain for domain in output_domains if domain not in input_domains and domain !=""] # list comprehension version
	save_to_file(_2nd_order_domains,"second-order-subdomains.txt")
	return _2nd_order_domains


def urls_to_domains_dict(file):
	'''
	make a dict of urls and domains from a file containing urls
	'''
	urls = file_to_list(file)
	domains2 = set()
	dict = {}

	for url in urls:
		d = urlparse(url).netloc
		domains2.add(d)
		dict.update({url:d})
	return dict,domains2 # returns a dictionary of urls:domains and a set of domains

def domain_urls(key,urls_file): #takes a domain name as key and gives corresponding urls
	dict,domains = urls_to_domains_dict(urls_file)
	urls = [x for x,y in dict.items() if y == key]
	print(urls)

def takeover_validate(domains_list,fingerprint_data,vuln_out_file):
	vuln_subs = []
	for d in domains_list:
		for prefix in ['http://', 'https://']: # Trying both HTTP and HTTPS where HTTPS has higher priority (Thus second in the list)
			try:
				r = requests.get('{}{}'.format(prefix, d), timeout=GLOBAL_HTTP_TIMEOUT, verify=False)
				content = r.text
			except:
				print(f'Could not connect to domain : {d}')

		# print(f'\n################ data for {d} ###################')
		for i in range(len(fingerprint_data)):
			if fingerprint_data[i]["fingerprint"] and fingerprint_data[i]["fingerprint"] in content:
				if fingerprint_data[i]["status"] == "Vulnerable":
					vuln_subs.append(d)
					print(f'	{Fore.LIGHTRED_EX}{d} : Status=VULNERABLE | Service={fingerprint_data[i]["service"]}{Fore.RESET}')
			# else:
			# 	print(f'{d} is NOT VULNERABLE')
			# print(fingerprint_data[i]['fingerprint'])
	
	save_to_file(vuln_subs,vuln_out_file)#save likely vulnerable 2nd order subdomains to a file
	return vuln_subs

def file_to_json(file): #takes a json file and return the data as a list
	with open(file,"r") as f: #load fingerprint data from 'can i takeover xyz
		content = f.read()
		json_list = json.loads(content)
	return json_list

def file_to_list(file):
	lines = []
	try:
		with open(file,'r') as f:
			for line in f.read().splitlines():
				lines.append(line)
		return lines
	except FileNotFoundError:
		print(f'\nSorry file "{file}" not found.\n')

#take positional and optional command line arguments for domains and fingerprints
parser = argparse.ArgumentParser()
parser.add_argument(
	"domains",
	help="Input domain list"
)
parser.add_argument(
	'-f',
	'--fingerprints',
	help='fingerprints file',
	default='fingerprints.json'
)
banner()
args = parser.parse_args()

#assigning command line args to variables
if args.domains:
	if file_to_list(args.domains):
		input_domains = file_to_list(args.domains)

if args.fingerprints:
	if file_to_json(args.fingerprints):
		fingerprints = file_to_json(args.fingerprints)

if __name__ == '__main__':
	# domains = sys.stdin.read().splitlines()
	print(f'[-] Scraping URLs from {Fore.LIGHTYELLOW_EX}{len(input_domains)}{Fore.RESET} domains')
	urls2 = [] #saves the urls of all domains
	for d in input_domains:
		for prefix in ['http://', 'https://']:
			# Trying both HTTP and HTTPS where HTTPS has higher priority
			# (Thus second in the list)
			try:
				r = requests.get('{}{}'.format(prefix, d), timeout=GLOBAL_HTTP_TIMEOUT, verify=False)
				content = r.text
			except:
				pass
		if r is None:
			# Connection refused / NXDOMAIN / ...
			continue
	
		urls = extract_javascript(d, content)
		urls += extract_styles(d, content)
		urls += extract_links(d, content)

		urls2.append(urls)

		urls2_len = list_len(urls2)

	urls_fn = 'urls.txt'
	print(f'[-] Saving scraped URLs to \'{urls_fn}\'')
	time.sleep(5)
	save_scraped_urls(urls2,urls_fn)
	print(f'[-] {Fore.LIGHTYELLOW_EX}{urls2_len}{Fore.RESET} URLs scraped and saved to \'{urls_fn}\'')


	#extract base domains from the second order urls generated
	second_order_domains = get_2nd_order_domains(args.domains,urls_fn)

	time.sleep(2)
	print(f'[-] {Fore.LIGHTYELLOW_EX}{len(second_order_domains)}{Fore.RESET} 2nd order subdomains extracted from {Fore.LIGHTYELLOW_EX}{urls2_len}{Fore.RESET} URLs and saved to \'second-order-subdomains.txt\'')
	time.sleep(2)
	print(f'[-] Validating {Fore.LIGHTYELLOW_EX}{len(second_order_domains)}{Fore.RESET} 2nd order subdomains for possible takeover')
	time.sleep(5)

	#validation 2nd order domains for takeover against fingerprints from 'can i take over xyz'
	vuln_out_fn = "vuln_domains.txt"
	vuln_subdomains = takeover_validate(second_order_domains,fingerprints,vuln_out_fn)
	print(f'[+] {Fore.LIGHTYELLOW_EX}{len(vuln_subdomains)}{Fore.RESET} Vulnerable subdomains found and saved to \'{vuln_out_fn}\'')

	et = time.time()
	elapsed = et - st
	ft = time.strftime("%H:%M:%S",time.gmtime(elapsed))
	print(f'Execution time : {ft}')




