# Web Requests



![url](/Users/valentinneher/Desktop/Development/hackthebox/web_requests/url.png)

Default port if not specified:

- http: `80`
- https: `443`



www.google.com is a subdomain of the Top Level Domain (TLD) google.com



### curl

- Bypass HTTPS force with `k`: `curl -k https://inlanefreight.com`
- Download `index.html` with: `curl -O google.com`
- Download with custom name: `curl inlanefreight.com/download.php -o myfile.php`
- Change User Agens with Flag `-A`: `curl https://inlanefreight.com -A 'Mozilla/5.0'`
- Show request and response headers with `-v -I` verbose + show only headers: `curl https://www.inlanefreight.com -v -I -A 'Mozilla/5.0'`



### HTTP

**Note:** HTTP version 1.X sends requests as clear-text, and uses a new-line character to separate different fields and different requests. HTTP version 2.X, on the other hand, sends requests as binary data in a dictionary form.





