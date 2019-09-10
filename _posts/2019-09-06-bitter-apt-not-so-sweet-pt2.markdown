---
layout: post
title:  "09/09/2019 - BITTER APT: Not So Sweet pt. 2"
date:   2019-09-09 00:00:00 -0700
categories: tech
author: MELTX0R
---
<center><img src="{{site.baseurl}}/assets/images/bitterBanner.jpg" style="max-width:100%;max-height:100%;"></center>

&nbsp;

## Summary

In [my last post](https://meltx0r.github.io/tech/2019/09/06/bitter-apt-not-so-sweet.html) I reviewed a recent BITTER campaign which used the ArtraDownloader and was observed targeting Pakistani organizations. This post is a continuation of my tracking efforts of the APT group known as "BITTER", in which I review additional undiscovered infrastructure and their Remote Access Trojan (RAT) known as BitterRAT.

## Analysis


While conducting research, I came across a binary (*d8b2cd8ebb8272fcc8ddac8da7e48e01*) on VirusTotal that was uploaded on 2019-07-27. According to an automated comment by THOR APT Scanner, this binary triggered detections for the rule "*APT_RAT_Patchwork_Jan19_2*". Reviewing the Command & Control communications for this binary confirmed it to be BitterRAT, a RAT used by the BITTER APT group as well as others (such as Patchwork, Hangover, etc.) in the past. The Command & Control for this binary was sent to *blth32serv.net* *(82.221.129.19)*. During my analysis, one thing that stood out as particularly interesting was that this binary utilized a certificate that appears to belong to the Sindh Police, which is headquartered in Karachi, Pakistan. The certificate is now expired (it was only valid from 7/25/2019 to 8/25/2019) and is giving warnings that the certificate cannot be verified. A recent [Tweet](https://twitter.com/RedDrip7/status/1170988245561294850) by the RedDrip team reaffirm these findings, in which they state that BITTER had stolen the aforementioned certificate.


&nbsp;


<center><img src="{{site.baseurl}}/assets/images/StolenCertificate_BITTERAPT_09092019.PNG" style="max-width:100%;max-height:100%;"></center>
<span style="font-size:small;"> Shown above: Certificate of BitterRAT binary</span>

&nbsp;



Armed with the information that *blth32serv.net* is the primary C2 for this BitterRAT sample, I then pivoted into VirusTotal's relational graphing to see if I could gather additional information on this campaign's infrastructure. This revealed another binary, *nsdtcv.exe (596ec0f90c25fdbe3d8ade3f4ea4cd38)*, that beacons to *blth32serv.net* as it's primary Command & Control. This second binary is currently being served via the URL *w32infinitisupports.net/win/ctf (94.156.175.61)* - at the time of this writing, I cannot find anything indicating this domain is known or being tracked in relation to BITTER APT.

&nbsp;


<center><img src="{{site.baseurl}}/assets/images/BITTER_RAT_VT_GRAPH_09092019.PNG" style="max-width:100%;max-height:100%;"></center>
<span style="font-size:small;"> Shown above: VirusTotal Graph of this campaign's infrastructure</span>

&nbsp;


Analysis of this secondary binary produced results that I would expect to see from BitterRAT - such as persistence via an autorun registry key, C2 via GET requests containing the URI pattern "*.php?TIe=[encoded data]*", etc.

&nbsp;


<center><img src="{{site.baseurl}}/assets/images/BITTERRAT_C2_09092019.PNG" style="max-width:100%;max-height:100%;"></center>
<span style="font-size:small;"> Shown above: Packet capture of BitterRAT C2</span>

&nbsp;


The data contained within the URI is encoded by adding to each byte within the string. By subtracting one from each byte, you are able to decode the data, which reveals that it is a unique identifier and the compromised machine's hostname. This is the same encoding technique I observed in my earlier [post](https://meltx0r.github.io/tech/2019/09/06/bitter-apt-not-so-sweet.html) regarding ArtraDownloader.

&nbsp;


| Unique Identifier | Hostname |
| 20052c37-1320-41a4-b58d-2b75a2850d2f | User-PC |

&nbsp;


Another interesting find is that both binaries contain PDB (Program Database) file strings. Program database files are generated when a file is compiled and contain debugging information about an individual build of a program, and can give us some unique insight into how these attackers build and store their malware. FireEye released a great article describing the importance of PDB's, which can be found [here](https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html).

&nbsp;

<span style="font-size:small;"> Shown below: PDB string found in the two BitterRAT binaries</span>
{% highlight text %}
C:\Users\Asterix\Documents\Visual Studio 2008\Projects\25July2019DN\Release\25July2019DN.pdb
{% endhighlight %}

&nbsp;


Within this fully qualified PDB path, I see several things of note. A username (*Asterix*), a project folder (*25July2019DN*), and the .pdb file itself (*25July2019DN.pdb*). From this, I can deduce that the creator of both of these binaries was (atleast at this stage in compilation) named *Asterix*, and that it was being worked on around the 25th of July 2019. Both files metadata reveal final compilation dates of July 25th 2019 04:55:52 for the first binary, and August 31st 2019 09:14:04 for the second binary. It is also interesting to see how these actors work on their malware in a structured way as any programmer might.

&nbsp;


Now that I was able to obtain the PDB string from these files, I can perform searches for similar files via VirusTotal's "RetroHunt" service (requires a paid subscription) or Hybrid-Analysis's advanced Yara search (free for a limited amount of results). In either case, I must first create a Yara rule to search for the PDB string. For this, I will only use the *"C:\Users\Asterix\"* portion of the PDB string, as I want to see what other files this user has authored.

&nbsp;


{% highlight yara %}
rule BITTER_RAT_PDB_STRING{
 strings:
   $a1 = "C:\\Users\\Asterix" nocase
 condition:
   $a1
}
{% endhighlight %} <span style="font-size:small;"> Shown above: A very basic example of a Yara rule</span>


&nbsp;


This search on Hybrid-Analysis returns 180 samples containing this string, 11 of which are available to view for free and 169 which require a paid subscription. Of the samples available for free, a majority of them are tagged "Hangover", indicating the APT group that goes by that name (according to [MITRE](https://attack.mitre.org/groups/G0040/), it is believed that the actors behind Patchwork APT are the same actors behind Hangover). Interestingly, they share several commonalities with the BITTER APT group - those being they both are believed to have a goal of espionage, both were first observed in late 2015, and both are believed to be pro-Indian or made up of Indian entities. I could not find any information online suggesting that Patchwork/Hangover may also be the same entity as BITTER, but it does show an interesting overlap in TTPs (Tactics, Techniques, & Procedures) and possible motives.

&nbsp;


Regardless, the earliest file creation date I am able to see from the free samples available matching that .PDB string is *February 2nd 2018*, indicating that the user "*Asterix*" has been involved in BITTER/Patchwork/Hangover operations for some time.  Based on the stolen certificate used for the first binary, I would extrapolate that the aforementioned files were used in attacks against Pakistani organizations, however I do not have further evidence at this time to confirm target attribution.



&nbsp;

## Indicators

| **Indicator** | **Type** | **Description** |
| blth32serv.net | Domain | BitterRAT C2 Domain |
| /ourtyaz/qwe.php?TIe=[encoded information] | URI | BitterRAT C2 URI Pattern |
| w32infinitisupports.net/win/ctf | URL | URL serving BitterRAT binary |
| 596ec0f90c25fdbe3d8ade3f4ea4cd38 | MD5 | Hash value for BitterRAT binary "nsdtcv.exe", served from w32infinitisupports.net |
| d8b2cd8ebb8272fcc8ddac8da7e48e01 | MD5 | Hash value for BitterRAT binary |
| 82.221.129.19 | IP Address | IP Address hosting blth32serv.net |
 | 94.156.175.61 | IP Address | IP Address hosting w32infinitisupports.net |
| C:\Users\Asterix\Documents\Visual Studio 2008\Projects\25July2019DN\Release\25July2019DN.pdb | PDB String | PDB String of two BitterRAT binaries |

&nbsp;

## References/Further Reading

1. https://www.fireeye.com/blog/threat-research/2019/08/definitive-dossier-of-devilish-debug-details-part-one-pdb-paths-malware.html
2. https://twitter.com/RedDrip7/status/1170988245561294850
3. https://attack.mitre.org/groups/G0040/
