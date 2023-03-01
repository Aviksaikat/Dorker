#!/usr/bin/python3
import argparse
from os import mkdir
import re
import urllib.parse

def get_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-t", "--target", dest="target", help="target")
	parser.add_argument("-o", "--output", dest="output", help="output")
	option = parser.parse_args()
	return option

def dork_to_link(dork, target):
    dork = dork.replace("{target}", f"{target}")
    #print(dork)
    #exit(1)
    #dork = urllib.parse.quote(dork)
    link = '<a href="https://www.shodan.io/search?query=' + urllib.parse.quote(dork) + '">' + dork + '</a><br>'
    print(link)
    return link

def shodan_dorking(f, target):
	# List of dorks
	dorks = [
		'ssl: "{target}" 200 http.title:"dashboard"',
	    'http.html:"Wordpress" org:{target}',
	    'http.html:"Discourse" org:{target}',
	    'http.html:"Grafana" org:{target}',
	    'http.html:"Jenkins" org:{target}',
	    'http.html:"MongoDB" org:{target}',
	    'http.html:"JBoss" org:{target}',
	    'http.html:"Drupal" org:{target}',
	    'http.html:"Joomla" org:{target}',
	    'http.html:"Kibana" org:{target}',
	    'http.html:"Elastic" org:{target}',
	    'http.html:"Elasticsearch" org:{target}',
	    'http.html:"Docker"  org:{target}',
	    'http.html:"Kubernetes" org:{target}',
	    'http.html:"Redis" org:{target}',
	    'http.html:"Citrix" org:{target}',
	    'http.html:"Outlook" org:{target}',
	    'http.html:"Owa" org:{target}',
	    'http.html:"Index of /" org:{target}',
	    'http.html:"DisallowedHost at /" org:{target}',
	    'http.html:"InfluxDB" org:{target}',
	    'http.html:"Apache Kafka" org:{target}',
	    'http.html:"Apache Tomcat" org:{target}',
	    'http.html:"Prometheus" org:{target}',
	    'http.html:"Logstash" org:{target}',
	    'http.html:"Terraform" org:{target}',
	    'http.html:"Jira" org:{target}',
	    'http.html:"Atlassian" org:{target}',
	    'http.html:"Confluence" org:{target}',
	    'http.html:"GraphQL" org:{target}',
	    'http.html:"Gitlab" org:{target}',
	    'http.html:"Git" org:{target}',
	    'http.html:"Github" org:{target}',
	    'http.html:"Postman" org:{target}',
	    'http.html:"Swagger UI" org:{target}',
	    'http.html:"nagios" org:{target}',
	    "ssl.cert.subject.cn:\"{target}\" http.title:\"admin\"",
		"ssl: \"{target}\" http.title: \"admin\"",
		"ssl.cert.subject.cn:\"{target}\" admin",
		"ssl: \"{target}\" admin",
		'port:21 "proftpd" org:{target}',
		'port:21 "220" "230 Login successful." org:{target}',
		'port:27017 "MongoDB Server Information" org:{target}',
		'port:22 OpenSSH org:{target}',
		'port:25 "exim" org:{target}',
		'port:80 "Apache httpd" org:{target}',
		'port:3389 "remote desktop" org:{target}',
		'product:"Apache httpd" org:{target}',
		'product:"OpenSSH" org:{target}',
		'product:"ciscoSystems" org:{target}',
		'product:"nginx" org:{target}',
		'product:"BigIP" org:{target}',
		'product:"Microsoft HTTPAPI httpd" org:{target}',
		'product:"Apache Tomcat/Coyote JSP engine" org:{target}',
		'product:"OpenResty" org:{target}',
		'product:"Postfix smtpd" org:{target}',
		'product:"MySQL" org:{target}',
		'product:"Exim smtpd" org:{target}',
		'product:"Kubernetes" org:{target}',
		'product:"AkamaiGHost" org:{target}',
		'product:"PostgreSQL" org:{target}',
		'product:"MiniServ" org:{target}',
		'product:"Grafana (Open Source)" org:{target}',
		'product:"SQL Server Browser Service" org:{target}',
		'product:"Apache Tomcat" org:{target}',
		'product:"Node.js" org:{target}',
		'product:"CouchDB" org:{target}',
		'product:"MongoDB" org:{target}',
		'product:"Memcached" org:{target}',
		'http.html:"Wordpress" org:{target}',
		'http.html:"Discourse" org:{target}',
		'http.html:"Grafana" org:{target}',
		'http.html:"Jenkins" org:{target}',
		'http.html:"MongoDB" org:{target}',
		'http.html:"JBoss" org:{target}',
		'http.html:"Drupal" org:{target}',
		'http.html:"Joomla" org:{target}',
		'http.html:"Kibana" org:{target}',
		'http.html:"Elastic" org:{target}',
		'http.html:"Elasticsearch" org:{target}',
		'http.html:"Docker"  org:{target}',
		'http.html:"Kubernetes" org:{target}',
		'http.html:"Redis" org:{target}',
		'http.html:"Citrix" org:{target}',
		'http.html:"Outlook" org:{target}',
		'http.html:"Owa" org:{target}',
		'http.html:"Index of /" org:{target}',
		'http.html:"DisallowedHost at /" org:{target}',
		'http.html:"InfluxDB" org:{target}',
		'http.html:"Apache Kafka" org:{target}',
		'http.html:"Apache Tomcat" org:{target}',
		'http.html:"Prometheus" org:{target}',
		'http.html:"Logstash" org:{target}',
		'http.html:"Terraform" org:{target}',
		'http.html:"Jira" org:{target}',
		'http.html:"Atlassian" org:{target}',
		'http.html:"Confluence" org:{target}',
		'http.html:"GraphQL" org:{target}',
		'http.html:"Gitlab" org:{target}',
		'http.html:"Git" org:{target}',
		'http.html:"Github" org:{target}',
		'http.html:"Postman" org:{target}',
		'http.html:"Swagger UI" org:{target}',
		'http.html:"nagios" org:{target}',
	]

	# Convert each dork to a link and concatenate into a single string
	links = ''
	for dork in dorks:
	    link = dork_to_link(dork, target)
	    links += link

	# Write links to file
	f.write('<html><body>\n')
	f.write(links)


def dorking(target, output):
	# GOOGLE DORKING
	mkdir(output)
	f = open(f'{output}/google-dorking.html', 'a')
	f.write(
		f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"> <title>Google Dorks for {target}</title> </head> <body><br>')
	# file extensions
	f.write('<h4>File Extensions</h4>')
	url = f"https://www.google.com/search?q=site%3A.{target}+filetype%3Aphp"
	f.write(f'<a target="_blank" href="{url}">PHP</a><br>')
	url = f"https://www.google.com/search?q=site%3A.{target}+filetype%3Aasp"
	f.write(f'<a target="_blank" href="{url}">ASP</a><br>')
	url = f"https://www.google.com/search?q=site%3A.{target}+filetype%3Aaspx"
	f.write(f'<a target="_blank" href="{url}">ASPX</a><br>')
	url = f"https://www.google.com/search?q=site%3A.{target}+filetype%3Ajsp"
	f.write(f'<a target="_blank" href="{url}">JSP</a><br>')
	
	# parameters
	f.write('<h4>Parameters</h4>')
	url = f"https://www.google.com/search?q=site%3A.{target}+inurl%3A%26"
	f.write(f'<a target="_blank" href="{url}">Parameters</a><br>')
	# Important stuffs
	f.write('<h4>Interesting Dorks</h4>')
	url = f"https://www.google.com/search?q=site%3A.{target}+intext%3A+%22index+of+%2F%22"
	f.write(f'<a target="_blank" href="{url}">Index of /</a><br>')
	url = f"https://www.google.com/search?q=site%3A.{target}+db_password+%3D%3D%3D"
	f.write(f'<a target="_blank" href="{url}">db_password ===</a><br>')
	url = f"https://www.google.com/search?q=site%3A.{target}+ext%3Aenv+|+ext%3Alog+|+ext%3Asql+|+ext%3Ayml+|+ext%3Apem+|+ext%3Aini+|+ext%3Alogs+|+ext%3Aibd+|+ext%3Atxt+|+ext%3Aphp.txt+|+ext%3Aold+|+ext%3Akey+|+ext%3Afrm+|+ext%3Abak+|+ext%3Azip+|+ext%3Aswp+|+ext%3Aconf+|+ext%3Adb+|+ext%3Aconfig+|+ext%3Aovpn+|+ext%3Asvn+|+ext%3Agit+|+ext%3Acfg+|+ext%3Aexs+|+ext%3Adbf+|+ext%3Amdb+ext%3Apem+ext%3Apub+ext%3Ayaml+ext%3Azip+ext%3Aasc+ext%3Axls+ext%3Axlsx"
	f.write(f'<a target="_blank" href="{url}">Interesting extensions</a><br>')

	# my custom dorks
	# GOOGLE
	google_dorks = [
		("site", f"{target} intext:\"access_token\""),
		("site", f"{target} intext:\"access_token\" -site:cloud.*"),
		("site", f"{target} intext:\"access_token\" -inurl:cloud"),
		("site", f"{target} intitle:\"index of\""),
		("site", f"{target} intitle:\"index of\" intext:\"passwd\""),
		("site", f"{target} intext:\"id_rsa\" -inurl:cloud|mirror AND intitle:\"index of\""),
		("site", f"{target} AND intext:'**one_of_password_pattern_value_here**'"),
		("", f"\"Org:{target}\": NPM_API_KEY="),
		("", f"\"Org:{target}\": NPM_API_TOKEN="),
		("", f"\"Org:{target}\": NPM_AUTH_TOKEN="),
		("", f"\"Org:{target}\": NPM_CONFIG_AUDIT="),
		("", f"\"Org:{target}\": NPM_CONFIG_STRICT_SSL="),
		("", f"\"Org:{target}\": NPM_EMAIL="),
		("", f"\"Org:{target}\": NPM_PASSWORD="),
		("", f"\"Org:{target}\": "),
		("", f"\"Org:{target}\": NPM_SECRET_KEY="),
		("org", f"{target} ftp"),
		("org", f"{target} Ldap"),
		("org", f"{target} https://"),
		("org", f"{target} language:python .php"),
		("site", f"{target} -www -shop -share -ir -mfa"),
		("site", f"pastebin.com \"{target}\""),
		("site", f"jsfiddle.net \"{target}\""),
		("site", f"codebeautify.org \"{target}\""),
		("site", f"codepen.io \"{target}\""),
		("site", f"{target} ext:php inurl:?"),
		("site", f"openbugbounty.org inurl:reports intext:\"{target}\""),
		("", f"(site:{target} | site:{target}) & \"choose file\""),
		("site", f"{target} \"index of\" inurl:ftp secret"),
		("site", f"{target} inurl:'/content/dam'")
	]

	for dork in google_dorks:
		query_type, query = dork
		query = urllib.parse.quote_plus(query)
		url = f"https://www.google.com/search?q={query_type}:{query}"
		f.write(f'<a target="_blank" href="{url}">{dork[1]}</a><br>')

	f.close()

	# VENDORKING
	k = f'https://www.{target}'
	ke = re.findall('\.\w.*\.', str(k))
	key = re.findall('\w.*\w', str(ke[0]))
	keyword = target
	f = open(f'{output}/vendorking.html', 'a')
	f.write(
		f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"> <title>Vendor Dorks for {keyword}</title> </head> <body><br>')
	vendors = ['.atlassian.net', 'bitbucket.org', 'bitpaste.app', 'codebeautify.org', 'codepad.co', 'codepad.org', 'codepen.io', 'codeshare.io', 'coggle.it', 'dotnetfiddle.net', 'dpaste.com', 'dpaste.org', 'github.com', 'gitlab.com', 'gitter.im', 'hastebin.com', 'heypasteit.com',
			   'ide.geeksforgeeks.org', 'ideone.com', 'jsdelivr.net', 'justpaste.it', 'libraries.io', 'npm.runit.com', 'npmjs.com', 'papaly.com', 'paste.debian.net', 'paste.org', 'paste2.org', 'pastebin.com', 'pastehtml.com', 'phpfiddle.org', 'prezi.com', 'repl.it', 'scribd.com', 'snipplr.com', 'trello.com']
	for vendor in vendors:
		url = f"https://www.google.com/search?q=site%3A%22{vendor}%22+%22{keyword}%22"
		f.write(f'<a target="_blank" href="{url}">{vendor}</a><br>')
	inurl_vendors = ["gitlab"]
	for x in inurl_vendors:
		url = f"https://www.google.com/search?q=inurl%3A%22{x}%22+%22{keyword}%22"
		f.write(f'<a target="_blank" href="{url}">{x}</a><br>')
	f.close()

	# GITHUB DORKING
	f = open(f'{output}/github-dorking.html', 'a')
	f.write(
		f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"> <title>Github Dorks for {target}</title> </head> <body><br>')
	list = ['filename:constants', 'filename:settings', 'filename:database', 'filename:config', 'filename:environment', 'filename:spec', 'filename:zhrc', 'filename:bash', 'filename:npmrc', 'filename:dockercfg', 'filename:pass', 'filename:global', 'filename:credentials', 'filename:connections', 'filename:s3cfg', 'filename:wp-config', 'filename:htpasswd', 'filename:git-credentials', 'filename:id_dsa', 'filename:id_rsa', 'extension:env', 'extension:cfg', 'extension:ini', 'language:yaml -filename:travis', 'extension:properties', 'extension:bat', 'extension:sh', 'extension:zsh', 'extension:pem', 'extension:ppk', 'extension:sql', 'extension:json', 'extension:xml', 'filename:bash_history', 'filename:bash_profile', 'filename:bashrc', 'filename:cshrc', 'filename:history', 'filename:netrc', 'filename:pgpass', 'filename:tugboat', 'filename:dhcpd.conf', 'filename:express.conf', 'filename:filezilla.xml', 'filename:idea14.key', 'filename:makefile', 'filename:gitconfig', 'filename:prod.exs', 'filename:prod.secret.exs', 'filename:proftpdpasswd', 'filename:recentservers.xml', 'filename:robomongo.json', 'filename:server.cfg', 'filename:shadow', 'filename:sshd_config', 'filename:known_hosts', 'filename:wp-config.php', 'filename:.env', 'filename:hub', 'filename:.netrc', 'filename:_netrc', 'filename:ventrilo_srv.ini', 'filename:dbeaver-data-sources.xml', 'filename:sftp-config.json', 'filename:.esmtprc password', 'filename:.remote-sync.json', 'filename:WebServers.xml', 'staging', 'stg', 'prod', 'preprod', 'swagger', 'internal', 'dotfiles', 'dot-files', 'mydotfiles', 'config', 'dbpasswd', 'db_password', 'db_username', 'dbuser', 'testuser', 'dbpassword', 'keyPassword', 'storePassword', 'passwords', 'password', 'secret.password', 'database_password', 'sql_password', 'passwd', 'pass', 'pwd', 'pwds', 'root_password', 'credentials', 'security_credentials', 'connectionstring', 'private -language:java', 'private_key', 'master_key', 'token', 'access_token', 'auth_token', 'oauth_token', 'authorizationToken', 'secret', 'secrets', 'secret_key', 'secret_token', 'api_secret', 'app_secret', 'appsecret', 'client_secret', 'key', 'send_keys', 'send.keys', 'sendkeys', 'apikey', 'api_key', 'app_key', 'application_key', 'appkey', 'appkeysecret', 'access_key', 'apiSecret', 'x-api-key', 'apidocs', 'secret_access_key', 'encryption_key', 'consumer_key', 'auth', 'secure', 'login', 'conn.login', 'sshpass', 'ssh2_auth_password', 'irc_pass', 'fb_secret', 'sf_username', 'node_env', 'aws_key', 'aws_token', 'aws_secret', 'aws_access', 'AWSSecretKey', 'github_key', 'github_token', 'gh_token', 'slack_api', 'slack_token', 'bucket_password', 'redis_password', 'ldap_username', 'ldap_password', 'gmail_username', 'gmail_password', 'codecov_token', 'fabricApiSecret', 'mailgun', 'mailchimp', 'appspot', 'firebase', 'gitlab', 'stripe', 'herokuapp', 'cloudfront',
			'amazonaws', 'npmrc _auth', 'pem private', 'aws_access_key_id', 'bashrc password', 'xoxp OR xoxb OR xoxa', 'FTP', 's3.yml', '.exs', 'beanstalkd.yml', 'deploy.rake', 'mysql', '.bash_history', '.sls', 'composer.jsonfilename:.npmrc _auth', 'filename:.dockercfg auth', 'extension:pem private', 'extension:ppk private', 'filename:id_rsa or filename:id_dsa', 'extension:sql mysql dump', 'extension:sql mysql dump password', 'filename:credentials aws_access_key_id', 'filename:.s3cfg', 'filename:.htpasswd', 'filename:.env DB_USERNAME NOT homestead', 'filename:.env MAIL_HOST=smtp.gmail.com', 'filename:.git-credentials', 'PT_TOKEN language:bash', 'filename:.bashrc password', 'filename:.bashrc mailchimp', 'filename:.bash_profile aws', 'rds.amazonaws.com password', 'extension:json api.forecast.io', 'extension:json mongolab.com', 'extension:yaml mongolab.com', 'jsforce extension:js conn.login', 'SF_USERNAME salesforce', 'filename:.tugboat NOT _tugboat', 'HEROKU_API_KEY language:shell', 'HEROKU_API_KEY language:json', 'filename:.netrc password', 'filename:_netrc password', 'filename:hub oauth_token', 'filename:filezilla.xml Pass', 'filename:recentservers.xml Pass', 'filename:config.json auths', 'filename:config irc_pass', 'filename:connections.xml', 'filename:express.conf path:.openshift', 'filename:.pgpass', '[WFClient] Password= extension:ica', 'filename:server.cfg rcon password', 'JEKYLL_GITHUB_TOKEN', 'filename:.bash_history', 'filename:.cshrc', 'filename:.history', 'filename:.sh_history', 'filename:prod.exs NOT prod.secret.exs', 'filename:configuration.php JConfig password', 'filename:config.php dbpasswd', 'filename:config.php pass', 'path:sites databases password', 'shodan_api_key language:python', 'shodan_api_key language:shell', 'shodan_api_key language:json', 'shodan_api_key language:ruby', 'filename:shadow path:etc', 'filename:passwd path:etc', 'extension:avastlic "support.avast.com"', 'extension:json googleusercontent client_secret', 'HOMEBREW_GITHUB_API_TOKEN language:shell', 'xoxp OR xoxb', '.mlab.com password', 'filename:logins.json', 'filename:CCCam.cfg', 'msg nickserv identify filename:config', 'filename:settings.py SECRET_KEY', 'filename:secrets.yml password', 'filename:master.key path:config', 'filename:deployment-config.json', 'filename:.ftpconfig', 'filename:sftp.json path:.vscode', 'filename:jupyter_notebook_config.json', '"api_hash" "api_id"', '"https://hooks.slack.com/services/"', 'filename:github-recovery-codes.txt', 'filename:gitlab-recovery-codes.txt', 'filename:discord_backup_codes.txt', 'extension:yaml cloud.redislabs.com', 'extension:json cloud.redislabs.com', 'stage', '_key', '_token', '_secret', 'TODO', 'signup', 'register', 'admin', 'administrator', 'testing', 'extension:exs', 'extension:sls', 'filename:beanstalkd.yml', 'filename:deploy.rake', 'filename:composer.json', 'ftp', 'ssh']
	for dork in list:
		url = f"https://github.com/search?q=%22{target}%22+{dork}&type=Code&o=desc&s="
		f.write(f'<a target="_blank" href="{url}">{dork}</a><br>')
	f.write(
		f'<br><br><h2>Using Keyword</h2><br><br>')
	k = f'https://www.{target}'
	ke = re.findall('\.\w.*\.', str(k))
	key = re.findall('\w.*\w', str(ke[0]))
	keyword = str(key[0])
	for dork in list:
		url = f"https://github.com/search?q=%22{keyword}%22+{dork}&type=Code&o=desc&s="
		f.write(f'<a target="_blank" href="{url}">{dork}</a><br>')
	f.write(
		f'<br><br><h2>Organization query</h2><br><br>')
	for dork in list:
		url = f"https://github.com/search?q=org%3A%22{keyword}%22+{dork}&type=Code&o=desc&s="
		f.write(f'<a target="_blank" href="{url}">{dork}</a><br>')
	f.close()

	# SHODAN DORKING
	f = open(f'{output}/shodan-dorking.html', 'a')
	f.write(
		f'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"> <title>Shodan Dorks for {keyword}</title> </head> <body><br>')
	f.write(
		f'<a target="_blank" href="https://www.shodan.io/search?query=hostname%3A{target}">Hostname</a><br><br>')
	f.write(
		f'<a target="_blank" href="https://www.shodan.io/search?query=org%3A{keyword}">Keyword</a><br><br>')

	shodan_dorking(f, target)
	f.close()

	
options = get_arguments()
if options.target and re.match("^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$", options.target):
	try:
		dorking(options.target, options.output)
		print(f"\n[+] Success. Please check the {options.target} directory.\n")
	except Exception as e:
		print(e)
		#print(f"\n[-] Directory '{options.target}' is already present.\n")
else:
	print("\n[-] Usage: python3 nDorker.py -t example.com -o output_dir\n")
