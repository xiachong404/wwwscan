#!/usr/bin/python
# coding=utf-8

#逐一读取ip.txt中的ip列表
#通过masscan扫描网段
#nmap识别端口服务
#生成report.csv列表


import re
import nmap
import datetime
import requests
import chardet
import json
import os
import socket
import re
from IPy import IP
from prettytable import PrettyTable
# import lib.threadPool
from lib.threadPool import ThreadPool

# requests.packages.urllib3.disable_warnings()
import urllib3
urllib3.disable_warnings()
import sys

reload(sys)
sys.setdefaultencoding('utf8')

# final_domains = []
final_reports = []
# ip_network_id = None
my_path = os.path.dirname(os.path.realpath(__file__)) #当前路径
my_file = os.path.dirname(os.path.realpath(__file__)) + r'/report.csv'


# 调用masscan
def portscan(ip_network):
    temp_ports = []  # 设定一个临时端口列表
    ports = []
    # cmd = my_path +'/bin/masscan ' + ip_network + ' -p 1-65535 -oJ ' + my_path + '/log/masscan.json --rate 2000'
    cmd = my_path +'/bin/masscan ' + ip_network + ' --top-ports 2000 -oJ ' + my_path + '/log/masscan.json --rate 2000'
    print "[*]"+ip_network+"扫描任务开始"
    print "[*]执行"+cmd
    with open(my_path + r'/log/log.txt', 'ab+') as ff:
		ff.write( cmd )
    os.system(cmd)
    # 提取json文件中的端口
    with open(my_path + '/log/masscan.json', 'r') as f:
        for line in f:
            if line.startswith('{ '):
                temp = json.loads(line)
                temp1 = temp["ports"][0]
                ports.append(str(temp1["port"]) + '|' + temp["ip"])
    return ports


# 获取网站的web应用程序名和网站标题信息
def Title(ip, port, service_name):
	try:
		scan_url_port = ''
		if service_name == '':
			service_name = None
		# final_report_dict = {'ip':ip,'port':port,'service_name':service_name,'is_web':'','url':'','rongqi':'','title':'','status_code':'','content_len':''}
		final_report_dict = {}
		if 'http' in service_name or service_name == 'sun-answerbook':
			if service_name == 'https' or service_name == 'https-alt':
				scan_url_port = 'https://' + ip + ':' + str(port)
				# Title(scan_url_port, service_name)
			else:
				scan_url_port = 'http://' + ip + ':' + str(port)
				# Title(scan_url_port, service_name)
		else:  # 唱跳rap和篮球C+V ,又是嫌弃速度慢了删除这
			scan_url_port = 'http://' + ip + ':' + str(port)  # <--
			# Title(scan_url_port, service_name)  # <--

		r = requests.get(scan_url_port, timeout=5, verify=False, stream=True)
		banner = r.headers['server']
		if banner.strip() == '':
			banner = None
		else:
			banner = banner.strip()
		# 获取网站的页面编码
		if 'Content-Length' in r.headers.keys() and int(r.headers['Content-Length']) > 5000000:  # 有些人特别坏访问端口让你下载个几g的文件
			# final_domains.append('[*]主机 ' + scan_url_port + ' 端口服务为：' + service_name + '大文件')
			final_report_dict = {'ip':ip,'port':str(port),'service_name':service_name,'is_web':'1','url':scan_url_port,'rongqi':banner,'title':'大文件','status_code':str(r.status_code),'content_len':str(r.headers['Content-Length']) }
			final_reports.append(final_report_dict)
		else:
			r_detectencode = chardet.detect(r.content)
			actual_encode = r_detectencode['encoding']
			response = re.findall(u'<title>(.*?)</title>', r.content, re.S)
			if response == []:
				# final_domains.append(
				# 	scan_url_port + '\t \t' + "".join(service_name.split()) + '\t' + str(r.status_code) + '\t' + str(
				# 		len(r.content)))
				final_report_dict = {'ip':ip,'port':str(port),'service_name':service_name,'is_web':'1','url':scan_url_port,'rongqi':banner,'title':None,'status_code':str(r.status_code),'content_len':str(len(r.content)) }
				final_reports.append(final_report_dict)
			else:
				# 将页面解码为utf-8，获取中文标题
				res = response[0].decode(actual_encode).decode('utf-8')
				if res.strip() == '':
					res = None
				else:
					res = res.strip()
				# banner = r.headers['server']
				# final_domains.append(
				# 	scan_url_port + '\t' + "".join(banner.split()) + '\t' + ''.join(res.split()) + '\t' + str(
				# 		r.status_code) + '\t' + str(len(r.content)))
				final_report_dict = {'ip':ip,'port':str(port),'service_name':service_name,'is_web':'1','url':scan_url_port,'rongqi':banner,'title':res,'status_code':str(r.status_code),'content_len':str(len(r.content)) }
				final_reports.append(final_report_dict)
	except Exception as e:
		pass
		# final_domains.append('[*]主机 ' + scan_url_port + ' 端口服务为：' + service_name + '无法访问')
		final_report_dict = {'ip':ip,'port':port,'service_name':service_name,'is_web':'0','url':None,'rongqi':None,'title':None,'status_code':None,'content_len':None}
		final_reports.append(final_report_dict)


# 调用nmap识别服务
def NmapScan(scan_ip_port, data):
	nm = nmap.PortScanner()
	try:
		scan_ip_port = scan_ip_port.split('|')
		ret = nm.scan(scan_ip_port[1], scan_ip_port[0], arguments='-Pn,-sS')
		service_name = ret['scan'][scan_ip_port[1]]['tcp'][int(scan_ip_port[0])]['name']
		print '[*]主机 ' + scan_ip_port[1] + ' 的 ' + str(scan_ip_port[0]) + ' 端口服务为：' + service_name

		Title(scan_ip_port[1],scan_ip_port[0], service_name)

		# if 'http' in service_name or service_name == 'sun-answerbook':
		# 	if service_name == 'https' or service_name == 'https-alt':
		# 		scan_url_port = 'https://' + scan_ip_port[1] + ':' + str(scan_ip_port[0])
		# 		Title(scan_url_port, service_name)
		# 	else:
		# 		scan_url_port = 'http://' + scan_ip_port[1] + ':' + str(scan_ip_port[0])
		# 		Title(scan_url_port, service_name)
		# else:  # 唱跳rap和篮球C+V ,又是嫌弃速度慢了删除这
		# 	scan_url_port = 'http://' + scan_ip_port[1] + ':' + str(scan_ip_port[0])  # <--
		# 	Title(scan_url_port, service_name)  # <--

		# final_domains.append(scan_ip_port[1] + ':' + str(scan_ip_port[0]) + '\t' + service_name)
	except Exception as e:
		print e
		pass


def main(ip_network):
	try:

		items = portscan(ip_network)  # 进行masscan跑端口

		data = []
		dataList = {}
		for i in items:
			i = i.split('|')
			if i[1] not in dataList:
				dataList[str(i[1])] = []
			dataList[str(i[1])].append(i[0])
		for i in dataList:
			if len(dataList[i]) >= 50:
				for port in dataList[i]:
					items.remove(str(port) + '|' + str(i))  # 删除超过50个端口的
		pool = ThreadPool(20, 1000)
		pool.start(NmapScan, items, data, )
		

	except Exception as e:
		print e
		print 'Ip.Txt A Certain Line Format Error'
		pass

#None转为''
def none_to_kong(str):
	if str=="None":
		return ''
	else:
		return str

#字典转字符串
def dict_to_str(final_report):
	ip           = str(final_report['ip'])
	port         = str(final_report['port'])
	service_name = str(final_report['service_name'])
	is_web       = str(final_report['is_web'])
	url          = none_to_kong( str(final_report['url']) )
	rongqi       = none_to_kong( str(final_report['rongqi']) )
	title        = none_to_kong( value_convert(str(final_report['title'])) )
	status_code  = none_to_kong( str(final_report['status_code']) )
	content_len  = none_to_kong( str(final_report['content_len']) )

	list = []
	list.append(ip)
	list.append(port)
	list.append(service_name)
	list.append(is_web)
	list.append(url)
	list.append(rongqi)
	list.append(title)
	list.append(status_code)
	list.append(content_len)

	message = ",".join(list)
	return message

# 去掉value值中的换行符，双引号，逗号
def value_convert(value):
	# 处理value数据，有些value数据内容为html标签，换行符和双引号会打乱生成的csv表格
	key = value.replace("\n","<br>")
	key = key.replace('"','“')
	key = key.replace(',','，')
	return key

# 去掉windows中的换行符^M
def del_windows_m(ip):
	# ip = re.sub(r'[\x00-\xlf]','',ip) #替换有问题，先不管了
	ip = ip.replace("\n","")
	return ip

# 主程序
def run():
	global final_reports #全局变量需申明，否则会出错
	with open(my_file, 'ab+') as ff:
		ff.write( "ip, port, service_name, is_web, url, rongqi, title, status_code, content_len\n" )
	
	with open(my_path + '/ip.txt', 'r') as f:
		for line in f:
			line = del_windows_m(line)
			main(line)
			for final_report in final_reports:
				message = dict_to_str(final_report)
				with open(my_file, 'ab+') as ff:
					ff.write(message+ "\n")
			if len(final_reports) == 0 :
				print "[!]"+ line +" 扫描端口结果为0\n"
			else:
				print "[*]"+ line +" 扫描结果插入成功\n"
			final_reports = []


if __name__ == '__main__':
	run()
