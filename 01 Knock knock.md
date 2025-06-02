
### **Knock Knock by HTB** 


### **Scenario**

A critical Forela Dev server was targeted by a threat group. The Dev server was accidentally left open to the internet which it was not supposed to be. The senior dev Abdullah told the IT team that the server was fully hardened and it’s still difficult to comprehend how the attack took place and how the attacker got access in the first place. Forela recently started its business expansion in Pakistan and Abdullah was the one IN charge of all infrastructure deployment and management. The Security Team need to contain and remediate the threat as soon as possible as any more damage can be devastating for the company, especially at the crucial stage of expanding in other region. Thankfully a packet capture tool was running in the subnet which was set up a few months ago. A packet capture is provided to you around the time of the incident (1–2) days margin because we don’t know exactly when the attacker gained access. As our forensics analyst, you have been provided the packet capture to assess how the attacker gained access. Warning : This Sherlock will require an element of OSINT to complete fully.

---

Let’s begin by downloading the PCAP file and extracting its contents.  
 After unzipping, you’ll see the following files:

![](https://cdn-images-1.medium.com/max/1200/1*uOAIW87-_BzUIRFvMGvk6g.png)

I’ll be using Zeek to analyze the files in this lab.

You can obtain the official Zeek Docker image from [here](https://docs.zeek.org/en/master/install.html) .

The following command launches an interactive Zeek container, mounting your current directory to `/mnt` inside the container. This allows you to easily access and process files from your local folder using Zeek:

docker run -v $(pwd):/mnt -it zeek/zeek sh

To load and analyze the PCAP file with Zeek, use the following command:

zeek -C -r capture.pcap local

- `-C` preserves the original packet contents, including checksums.
- `-r capture.pcap` tells Zeek to read and process the specified capture file.
- `local` loads the default local Zeek scripts for analysis.

Note: Handy [cheatsheet](https://github.com/corelight/zeek-cheatsheets/blob/master/Corelight-Zeek-Cheatsheets-3.0.4.pdf) with commonly used Zeek commands and tips to help you analyze network traffic efficiently.

---

  

Let’s begin our investigation by examining the available logs. We’ll start with the HTTP log, as it often contains valuable information that can provide useful insights.

These are the values I am going to check first .

![](https://cdn-images-1.medium.com/max/1200/1*-SAVrRrs1vAQCzIyWTLozg.png)

```
less -S http.log | zeek-cut username password uri method status_code | sort | uniq
```

We identified an interesting file that was downloaded.

![](https://cdn-images-1.medium.com/max/1200/1*m7eYGDBdTiVHTJzJov8RiA.png)

I want to investigate this file further by identifying both the originating host and the responding host involved in the download. 
```
less -S http.log | zeek-cut  uri id.orig_h id.resp_h  | grep Ransomware2_server.zip
```

![](https://cdn-images-1.medium.com/max/1200/1*ZBVEW8EG99DpQlm-VyTDRg.png)

172.31.39.46 is the host that downloaded the file.

Next, let’s review the contents of the downloaded file. To enable this, we need to modify Zeek’s configuration file located at `/usr/local/zeek/share/zeek/site/local.zeek`.  
 

I will add the `**usr/local/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek**` framework to the `local.zeek` file.

![](https://cdn-images-1.medium.com/max/1200/1*jMAEIR72Pknx5uAcgcs7fQ.png)

![](https://cdn-images-1.medium.com/max/1200/1*vnwQUW8MNUzVtKJ9g3Y-CQ.png)

Now, let’s run Zeek again with the updated configuration to analyse the capture file:

```
zeek -C -r capture.pcap local
```

Now, all extracted files will be available for analysis. We can proceed to examine their contents.

![](https://cdn-images-1.medium.com/max/1200/1*8bZSwWTACaJg68dyySItPw.png)

  

I will need the `resp_fuids` value, which serves as the file’s unique identifier. This will allow me to extract the specific file from the logs.

![](https://cdn-images-1.medium.com/max/1200/1*TNUi3QbemWaszZSX09nZHw.png)

Here is the file we need.

![](https://cdn-images-1.medium.com/max/1200/1*a350_v_71phaag8UCl_57A.png)

After unzipping the file, we discover that the ransomware is named **GonnaCry**.

![](https://cdn-images-1.medium.com/max/1200/1*5cNNmAJWT4s6UgpJW8EhbA.png)

---

![](https://cdn-images-1.medium.com/max/1200/1*JIHru3c2Tht6WvRLQBNFmA.png)

To view FTP passwords in clear text, we need to edit the following Zeek script **`/usr/local/zeek/share/zeek/base/protocols/ftp/main.zeek`**

![](https://cdn-images-1.medium.com/max/1200/1*Xn2Y9l0OvRV2Kphc2VT64Q.png)

Comment out these lines in the script to enable the display of passwords in clear text.

 ```
less -S ftp.log | zeek-cut user password id.resp_h id.orig_h command arg fuids reply_msg fuid | sort | uniq
```

![](https://cdn-images-1.medium.com/max/1200/1*x4IGQKU3IAYnwLIoTlMNMQ.png)

We can now view users and their FTP passwords, along with the files downloaded via FTP and their unique IDs, as well as the source and destination IP addresses.

Let’s examine the files one by one.

1 — **reminder.txt** file

![](https://cdn-images-1.medium.com/max/1200/1*Fo6DjN0mp7qNznmsa3Xriw.png)

2- **archived.sql** file

![](https://cdn-images-1.medium.com/max/1200/1*VakuARleRyjEH7tdZRCmkw.png)

3-**backup** file

![](https://cdn-images-1.medium.com/max/1200/1*mJ7Wsg8z68njkFSah1udnA.png)

This extracted file contains an automated rule that enables network access through port-knocking, using the port sequence **29999, 50234, 45087**. It also reveals credentials for another backup server. Attackers could exploit this information to gain access to internal systems or escalate their privileges further.

4- **fetch.sh** file

![](https://cdn-images-1.medium.com/max/1200/1*pDZoTYAoenOdgb4mBNrMCw.png)

5- **/etc/passwd** file

![](https://cdn-images-1.medium.com/max/1200/1*2NdCTRr41LItgMlWDNXMkA.png)

6- **.reminder** file

![](https://cdn-images-1.medium.com/max/1200/1*oxw0ym_5JlAcwT7QGDi_8w.png)

---

Next, we’ll analyse the `conn.log` file, as it is likely to contain valuable information about network connections and activity.  

```
less -S conn.log | zeek-cut id.resp_h id.orig_h | sort | uniq -c | sort -n

less -S conn.log | zeek-cut id.resp_h id.orig_h | sort | uniq -c | sort -n
```

![](https://cdn-images-1.medium.com/max/1200/1*0TJ3PnAaVdn8TqHfYgDt2g.png)

The majority of connections originate from the IP address **3.109.209.43**, with a total of 65,641 connections. This high volume of connections is indicative of likely port scanning activity.

Let’s confirm this theory by taking a closer look at the connection patterns and behaviors.

```
less -S conn.log | zeek-cut id.resp_h id.orig_h  id.resp_p   conn_state  | grep 3.109.209.43 | head -n  30
```

![](https://cdn-images-1.medium.com/max/1200/1*iWVX_PtNDgaNtaoiGynq1w.png)

It’s evident that **3.109.209.43** is attempting to connect to ports sequentially, and the extremely rapid timestamps indicate that these connections are being made by an automated tool rather than manual activity.

---

Now, let’s move on to the questions.

**Question 1 — Which ports did the attacker find open during their enumeration phase?**

We observed a port knocking sequence — 29999, 50234, 45087 — that was used to open specific ports. The question requires us to identify which ports were open during the enumeration phase, so we need to examine the logs for ports that were accessible before the port knocking occurred.

First, we’ll compile a list of all the ports that were rejected.
```

less -S conn.log | zeek-cut id.resp_p conn_state id.orig_h | grep 3.109.209.43 | awk '$2=="REJ" {print "^"$1"$"}' > rejected_ports
```
Next, we’ll generate a separate list of all the ports that were accepted.
```
less -S conn.log | zeek-cut id.resp_p conn_state id.orig_h | grep 3.109.209.43 | awk '$2=="SF" {print $1}' > accepted_ports
```

Then, I’ll filter out the ports that appear in the accepted list but not in the rejected list. This will provide the list of ports that were open before the port knock occurred.

```
cat accepted_ports | grep -v -f rejected_ports
```


![](https://cdn-images-1.medium.com/max/1200/1*Zmq2c1rKnDLtklqEfc08YQ.png)

Answer: 21,22,3306,6379,8086

**Question 2 — Whats the UTC time when attacker started their attack against the server?**
```
less -S conn.log | zeek-cut id.orig_h ts id.resp_p  |  grep 3.109.209.43 | head
```

![](https://cdn-images-1.medium.com/max/1200/1*i9U6zRa9oE941TNfhHMCYQ.png)

Answer: 21/03/2023 10:42:23

**Question 3 :What’s the MITRE Technique ID of the technique attacker used to get initial access?**

Add `**PASS**` to **`/usr/local/zeek/share/zeek/base/protocols/ftp/main.zeek`** and we will see all the incorrect login attempts.
```
less -S ftp.log  | zeek-cut user password | sort | uniq
```

We observed that multiple usernames were targeted with various passwords in rapid succession, indicating that the initial compromise technique used was password spraying.

![](https://cdn-images-1.medium.com/max/1200/1*_oygP5GnwA_XIbtORG6wSg.png)

Answer: T1110.003

**Question 4 — What are valid set of credentials used to get initial foothold?**

Answer: tony.shephard:Summer2023!

**Question 5 —What is the Malicious IP address utilized by the attacker for initial access?**

Answer: 3.109.209.43

**Question 6 —  What is name of the file which contained some config data and credentials?**

Answer: .backup

**Question 7 — Which port was the critical service running?**
```
less -S ftp.log  | zeek-cut user password id.resp_p
```

![](https://cdn-images-1.medium.com/max/1200/1*NCwSDiKfQtZcKTeIdOcGCw.png)

Answer: 24456

**Question 8 — What is the name of technique used to get to that critical service?**

Answer: Port Knocking

**Question 9 — Which ports were required to interact with to reach the critical service?**

Answer: 29999,45087,50234

**Question 10 — Whats the UTC time when interaction with previous question ports ended?**

![](https://cdn-images-1.medium.com/max/1200/1*JLxEIVJgKfIOFjQ3ZtJHng.png)

![](https://cdn-images-1.medium.com/max/1200/1*w6idcEaP-Lp8sBUs3Wz1yw.png)

Answer: 21/03/2023 10:58:50

**Question 11 —  What are set of valid credentials for the critical service?**

Answer : abdullah.yasin:XhlhGame_90HJLDASxfd&hoooad

**Question 12 — At what UTC Time attacker got access to the critical server?**

```
less -S ftp.log | zeek-cut user password ts | grep abdullah.yasin | head
```

![](https://cdn-images-1.medium.com/max/1200/1*g5nIrlFNg71x0J8tlyWvaQ.png)

Answer: 21/03/2023 11:00:01

**Question 13: Whats the AWS AccountID and Password for the developer “Abdullah”?**

Answer: We found it earlier in archieved.sql file from FTP.

  

![](https://cdn-images-1.medium.com/max/1200/1*VakuARleRyjEH7tdZRCmkw.png)

Answer: 391629733297:yiobkod0986Y[adij@IKBDS

**Question 14:Whats the deadline for hiring developers for forela?**

This information is contained in this file

![](https://cdn-images-1.medium.com/max/1200/1*WpZofL1tAqHE0A322ZaVRQ.png)

![](https://cdn-images-1.medium.com/max/1200/1*ieUFI6gVg_mV_DYz0wMCug.png)

Answer: 30/08/2023

**Question 15- When did CEO of forela was scheduled to arrive in pakistan?**

Answer is given in reminder.txt file .

  

![](https://cdn-images-1.medium.com/max/1200/1*Fo6DjN0mp7qNznmsa3Xriw.png)

Answer:08/03/2023

**Question 16 — The attacker was able to perform directory traversel and escape the chroot jail.This caused attacker to roam around the filesystem just like a normal user would. Whats the username of an account other than root having /bin/bash set as default shell?**

The `/etc/passwd` file stores all user account names on the system.

![](https://cdn-images-1.medium.com/max/1200/1*2NdCTRr41LItgMlWDNXMkA.png)

Answer : Cyberjunkie

**Question 17 — What’s the full path of the file which lead to ssh access of the server by attacker?**

Answer: /opt/reminders/.reminder

**Question 18 — Whats the SSH password which attacker used to access the server and get full access?**

![](https://cdn-images-1.medium.com/max/1200/1*oxw0ym_5JlAcwT7QGDi_8w.png)

The commit history of the Forela Git repository contains an SSH password.

![](https://cdn-images-1.medium.com/max/1200/1*-NV_0XsJXKxyu-aCoKD7Rg.png)

Answer : YHUIhnollouhdnoamjndlyvbl398782bapd

**Question 19 — Whats the full url from where attacker downloaded ransomware?**

We found this answer already in the above section.

![](https://cdn-images-1.medium.com/max/1200/1*tSaryDOS4_3Z2UcInZesqA.png)

Answer: [http://13.233.179.35/PKCampaign/Targets/Forela/Ransomware2_Server.zip](http://13.233.179.35/PKCampaign/Targets/Forela/Ransomware2_Server.zip)

**Question 20 — Whats the tool/util name and version which attacker used to download ransomware?**

![](https://cdn-images-1.medium.com/max/1200/1*teZ9TJ6P6PW5UF6uRjUeAw.png)

Answer : Wget/1.21.2

**Question 21 — Whats the ransomware name?**

We found this answer already in the above section.

![](https://cdn-images-1.medium.com/max/1200/1*UVFnoiojGe_NUYj1Vzv1rA.png)

Answer : GonnaCry .