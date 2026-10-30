/* Sample datasets for the demo buttons. */
const SAMPLES = {
  portscan: `[2024-01-15 03:42:11] TCP SYN 203.0.113.47:52341 -> 10.0.0.5:22
[2024-01-15 03:42:11] TCP SYN 203.0.113.47:52342 -> 10.0.0.5:23
[2024-01-15 03:42:11] TCP SYN 203.0.113.47:52343 -> 10.0.0.5:80
[2024-01-15 03:42:11] TCP SYN 203.0.113.47:52344 -> 10.0.0.5:443
[2024-01-15 03:42:11] TCP SYN 203.0.113.47:52345 -> 10.0.0.5:3389
[2024-01-15 03:42:11] TCP SYN 203.0.113.47:52346 -> 10.0.0.5:8080
[2024-01-15 03:42:12] TCP SYN 203.0.113.47:52347 -> 10.0.0.5:445
[2024-01-15 03:42:12] TCP SYN 203.0.113.47:52348 -> 10.0.0.5:1433
[2024-01-15 03:42:12] TCP SYN 203.0.113.47:52349 -> 10.0.0.5:3306
[2024-01-15 03:42:12] TCP SYN 203.0.113.47:52350 -> 10.0.0.5:5432
[2024-01-15 03:42:12] TCP SYN 203.0.113.47:52351 -> 10.0.0.5:6379
[2024-01-15 03:42:13] TCP SYN 203.0.113.47:52352 -> 10.0.0.5:27017
RST received on all ports. 12 ports probed in 2 seconds from single source.`,

  ddos: `[2024-01-15 14:22:00] Inbound traffic spike: 18.4 Gbps
[2024-01-15 14:22:00] UDP flood 198.51.100.0/24 -> 192.168.0.10:53  pps=450000
[2024-01-15 14:22:01] UDP flood 203.0.113.0/24  -> 192.168.0.10:53  pps=510000
[2024-01-15 14:22:01] Unique source IPs: 14302 (botnet suspected)
[2024-01-15 14:22:02] DNS amplification factor: 65x (ANY query, 4096-byte responses)
[2024-01-15 14:22:02] Packet sizes: 512–4096 bytes (irregular)
[2024-01-15 14:22:03] Server CPU: 98.7%
[2024-01-15 14:22:03] Legitimate traffic drop rate: 94.3%
[2024-01-15 14:22:04] BGP origins: AS57660, AS61855, AS39364 (bulletproof ASNs)`,

  malware: `[2024-01-15 09:15:44] DNS query: a1b2c3d4e5f6.domain-flux.ru  (src: 10.0.1.22)
[2024-01-15 09:15:45] DNS response: f6e5d4c3b2a1.domain-flux.ru -> 185.220.101.45
[2024-01-15 09:15:46] TCP established  10.0.1.22:49201 -> 185.220.101.45:4444
[2024-01-15 09:15:46] Encrypted payload: 256 bytes (non-standard cipher)
[2024-01-15 09:16:00] Beacon interval: 14 s (jitter ±2 s)
[2024-01-15 09:16:14] Outbound: 128 bytes (command-ack pattern)
[2024-01-15 09:16:28] DNS query: b3c4d5e6f7a8.domain-flux.ru  (DGA pattern)
[2024-01-15 09:16:29] HTTP POST 10.0.1.22 -> 91.108.4.166:80
[2024-01-15 09:16:29] User-Agent: "Mozilla/5.0 (compatible; MSIE 6.0)"
[2024-01-15 09:16:29] URI: /gate.php?id=abc123&version=2.1&os=win10`,

  exfil: `[2024-01-15 22:30:11] HTTPS POST 10.0.5.88:49502 -> 104.21.44.119:443  size=8.2 MB
[2024-01-15 22:30:14] HTTPS POST 10.0.5.88:49503 -> 104.21.44.119:443  size=7.9 MB
[2024-01-15 22:30:17] HTTPS POST 10.0.5.88:49504 -> 104.21.44.119:443  size=8.1 MB
[2024-01-15 22:30:20] Total outbound: 48.7 MB in 3 min  (normal baseline: 200 KB/hr)
[2024-01-15 22:30:20] Files accessed before transfer:
  \\\\finance\\Q4_earnings.xlsx
  \\\\hr\\salaries_2024.csv
  \\\\legal\\contracts\\NDA_signed\\
[2024-01-15 22:30:21] Account: svc_backup  (service account — unusual interactive login)
[2024-01-15 22:30:21] Login time: 22:30 (outside business hours)
[2024-01-15 22:30:22] Destination: Cloudflare CDN edge (TLS 1.3 ESNI)`,

  sqli: `[2024-01-15 11:05:00] HTTP GET /products?id=1  200 OK
[2024-01-15 11:05:02] HTTP GET /products?id=1'  500 ERROR
[2024-01-15 11:05:04] HTTP GET /products?id=1 OR 1=1--  200 OK  (all rows returned)
[2024-01-15 11:05:06] HTTP GET /products?id=1 UNION SELECT table_name,NULL FROM information_schema.tables--  200 OK
[2024-01-15 11:05:08] HTTP GET /products?id=1 UNION SELECT username,password FROM users--  200 OK
[2024-01-15 11:05:09] Response size: 14.2 KB  (normal: ~1.4 KB)
[2024-01-15 11:05:10] HTTP GET /admin/login  200 OK
[2024-01-15 11:05:12] HTTP POST /admin/login  username=admin&password=password123  302 REDIRECT
[2024-01-15 11:05:12] Admin session established  src: 77.88.55.60`,

  brute: `[2024-01-15 06:00:00] SSH FAILED  root@10.0.0.2  from 45.33.32.156
[2024-01-15 06:00:01] SSH FAILED  root@10.0.0.2  from 45.33.32.156
[2024-01-15 06:00:02] SSH FAILED  admin@10.0.0.2  from 45.33.32.156
[2024-01-15 06:00:03] SSH FAILED  administrator@10.0.0.2  from 45.33.32.156
[2024-01-15 06:00:04] SSH FAILED  ubuntu@10.0.0.2  from 45.33.32.156
[2024-01-15 06:00:05] SSH FAILED  pi@10.0.0.2  from 45.33.32.156
... [3841 further attempts over 12 min — 5.3 attempts/sec]
[2024-01-15 06:12:44] SSH SUCCESS  deploy@10.0.0.2  from 45.33.32.156
[2024-01-15 06:12:45] Shell spawned for user: deploy
[2024-01-15 06:12:46] Commands: whoami; id; uname -a; cat /etc/passwd`,

  normal: `[2024-01-15 10:00:01] DNS  www.google.com -> 142.250.74.4  (src: 10.0.0.15)
[2024-01-15 10:00:02] HTTPS GET 10.0.0.15 -> 142.250.74.4:443  200 OK  48 KB
[2024-01-15 10:00:05] HTTPS GET 10.0.0.15 -> 52.35.102.88:443 (slack.com)  200 OK
[2024-01-15 10:00:10] DNS  mail.google.com -> 74.125.196.19
[2024-01-15 10:00:11] HTTPS 10.0.0.15 -> 74.125.196.19:443  200 OK  1.2 KB
[2024-01-15 10:01:00] NTP sync 10.0.0.1 -> 216.239.35.0:123  OK
[2024-01-15 10:02:33] HTTPS GET 10.0.0.22 -> 18.184.99.128:443 (zoom.us)  200 OK
[2024-01-15 10:05:00] HTTP 10.0.0.1 -> 192.168.0.254:80 (router admin)  200 OK`
};
