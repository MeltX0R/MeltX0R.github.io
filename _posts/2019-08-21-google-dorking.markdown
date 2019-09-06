---
layout: post
title:  "Google Dorking"
date:   2019-08-27 00:00:00 -0700
categories: tutorial
author: MELTX0R
---

<center><img src="{{site.baseurl}}/assets/images/googling-stuff-confused.jpg" style="max-width:100%;max-height:100%;"></center>

&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;

<span style="font-size:large;font-style:italic">Google Dorking</span> sometimes referred to as "*Google Hacking*" can be a very useful resource for security analysts, penetration testers, threat researchers, and those with... less than helpful intentions.

The average user is familiar with Google - after all it is the most widely used search engine, with over 90% market share and over 5 billion searches every day. However, typical Google searches consist of entering basic terms or questions into the search bar - such as "taco recipes" or "why isn't 11 pronounced onety-one?". These differ from Google Dorking, which takes advantage of "*Advanced Operators*". An Advanced Operator is a special character or command that helps extend the capability of normal searches, thus forcing searches to return more specific or restricted results. For example, if I were to trying to find a very specific article published on cnn.com regarding gummy bears, and tried searching for `cnn gummy bears`, over 316k results would be returned.

&nbsp;

<center><img src="{{site.baseurl}}/assets/images/cnn-gummy-bear-search.jpg" style="max-width:100%;max-height:100%;"></center>

&nbsp;

However, if I were to utilize Advanced Operators in my query, and instead search for `site:cnn.com intitle:"gummy bears"` only 2 results are returned

&nbsp;

<center><img src="{{site.baseurl}}/assets/images/cnn-gummy-bear-dork.jpg" style="width:750px;height:150px;"></center>

&nbsp;

Where this becomes dangerous is when Google indexes, caches, and makes searchable, data that is sensitive. Google and other search engines are constantly crawling, indexing, and caching the internet. And while most of the data indexed/cached was meant for public viewing, some of it was unintentionally left "accessible" to these search engines. As a result, there are treasure troves of data out there that was indexed/cached by these search engines (including confidential information, passwords, files, and more), but require more specific search terms to find. In fact, this feature has been utilized so often by malicious actors that the FBI released a warning about the risks associated with Google Dorking in 2014 **[(found here)](https://info.publicintelligence.net/DHS-FBI-NCTC-GoogleDorking.pdf/)**.

Now, you may be thinking "that's great and all, but how can I actually use this in my job?" Great question! As someone who has defended networks and hunted for threats, I've had to use Google Dorking in many different ways - for example, if I wanted to search for compromised credentials that were uploaded to a Pastebin dump, I would use the search `site:pastebin.com "@[myDomain].com"`. You could even go a step further, and create a [Google Alert](https://www.google.com/alerts) to send you email notifications any time a new result is found for that search.

Or, if I wanted to find out if the company I am doing a penetration test for used PulseSecure VPN (which was recently identified as having a high severity arbitrary file reading vulnerability - [CVE-2019-11510](https://nvd.nist.gov/vuln/detail/CVE-2019-11510)) then I could do a Google search for `inurl:/dana-na/ filetype:cgi companyName` and see if the login page for PulseSecure VPN was cached by Google for that company.

In closing, there are a plethora of different ways you could use Google Dorking to find vulnerabilities, confidential information, and more. Fortunately for us, Exploit-DB.com maintains a database of Google Dorking searches and their use-cases, aptly named **[Google Hacking Database](https://www.exploit-db.com/google-hacking-database)**, which I highly recommend checking out. Experiment with different Advanced Operators (I included a table below) and see what you can find!

&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;

<span style="font-size:x-large;">Google Search Advanced Operator Table</span> <span style="font-size:small;"> <a href="https://en.wikipedia.org/wiki/Google_hacking"> taken from Wikipedia</a></span>

| Operator | Purpose |
| - |-|
| intitle|Search page Title|
| inurl|Search URL|
| allinurl|Search URL|
| filetype|specific files|
| intext|Search text of page only|
| allintext|Search text of page only|
| site|Search specific site|
| inanchor|Search link anchor text|
| numrange|Locate number|
| daterange|Search in date range|
| author|Group author search|
| group|Group name search|
| insubject|Group subject search|
| msgid|Group msgid search|

&nbsp;
&nbsp;
&nbsp;
&nbsp;
&nbsp;

<span style="font-size:large;">References/Further Reading</span>
1. https://en.wikipedia.org/wiki/Google_hacking
2. https://www.exploit-db.com/exploits/47297
3. https://info.publicintelligence.net/DHS-FBI-NCTC-GoogleDorking.pdf
4. https://en.wikipedia.org/wiki/Web_crawler
5. https://nvd.nist.gov/vuln/detail/CVE-2019-11510
