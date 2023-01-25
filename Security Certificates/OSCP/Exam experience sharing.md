# Exam experience sharing

## Introduction

OSCP (Offensive Security Certified Professional) is a professional network penetration testing certificate provided by Offensive Security company. It is a highly practical and challenging certificate that requires the examinee to pass a 24-hour actual penetration testing exam. In the exam, the examinee needs to complete the penetration testing of different systems within the given time and submit the penetration report online.

Examinees who pass the OSCP certificate need to have a high level of network security knowledge and practical experience, and be able to independently conduct network penetration testing and generate detailed penetration reports. This certificate can be used as a qualification certificate for network security professionals and can help examinees in their career development.

## Exam Structure

- The exam consists of three independent exam targets and a domain environment (three machines)
- Three independent machines, each with 20 points; domain environment 40 points, need to obtain the complete attack chain to get 40 points.
- Bonus points 10 points.
- The passing score for the exam is **70 points**.

## Fee Standard

At present, there are three official fee packages:

- 1599 US dollars (increased, 1499 US dollars before New Year's Day), including course, 90-day laboratory and one exam opportunity.
- 2499 US dollars (discounted to 1999 US dollars before New Year's Day), including course, one year laboratory time, two exam opportunities, one year PG laboratory, KLCP exam opportunity and OSWP exam opportunity.
- 5499 US dollars (suitable for tycoons), including one year laboratory time, unlimited exam attempts for all certificates of offensive official, but there is an exam cooling period.



## Personal Experience

### Warm-up

For preparing for OSCP, the basic practice is around several platforms of target machines:

- [vulnhub](https://www.vulnhub.com/), which contains some retired machines from the official exam, and can be downloaded for free for local practice.
- [HTB](https://www.hackthebox.com/), which has good machines and not too expensive, 14 US dollars per month.
- [tryhackme](https://tryhackme.com/), focusing on Windows AD, Linux Windows privilege escalation machines, and can be completed with one month's basic purchase.
- [PG](https://portal.offensive-security.com/labs/practice), the official practice target machine, can be completed with intermediate difficulty, 19 US dollars per month.

> Someone has summarized the target machines similar to the OSCP exam mode in these target machine platforms, please refer to: https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview

For the first three platforms, I directly find the walkthrough of the machine on the Internet and reproduce it one by one. If there is not much time for preparation, you can directly read the walkthrough article to **understand what types of exams are available, what tools are used, and what the attack chain is**. This content took me **three months**.

For the PG target machine, I first played it by myself. If I don't know, I can see the official walkthrough (one machine per day). This content took me **more than one month**. As I played more and more, I found that many contents had appeared in vulnhub and htb.

Therefore, I summarized some enumeration techniques:

- Check if there is any hidden content in the source code.
- Check if there is any CMS returned in the response headers.
- Check the config.php file in `/var/www/html`.
- Check if there is any MySQL connection and connect to check the information.
- FTP, SMB directory is the same as the web directory, upload webshell.
- Set the rebound shell port to 21, 22, 80, 443 and other common ports to prevent interception.
- SSH brute force username and password are the same.
- Check if there is any **virtual domain** in the source code.
- Pay attention to the CMS version may be wrong, if the search does not have vulnerabilities, try to use the low version EXP.
- Pay attention to whether the user ID group has problems.
- Soft link bypasses file or directory restrictions.
- Check the port service of 127.0.0.1 on the target field.
- See if there is a username on the WEB page, if so, try to register and see if it can be covered.
- Check for vulnerabilities or passwords in docker escape.
- If you encounter the `cgi-bin` directory, continue to brute force the cgi file format.
- If linpeas does not find anything, use pspy to monitor if there is a scheduled plan.



### buy oscp

Before buying, you must **apply for a passport**, the official needs to take a passport and face recognition, customer service manual review can access the resources. After certification, you can access course materials and laboratories, which involves **10 bonus points** content needs to be completed, which is the most important.

> **Topic Practice + 30 Lab Machines**
>
> - In order to obtain ten (10) bonus points, you must submit at least **80% of the topic practice solutions** correctly in each topic of the PEN-200 course, and submit **30 correct proof.txt hashes** in the Offsec platform.
> - There is no restriction on which laboratory machines are applicable for 30 correct proof.txt hashes. This means that it can include **Sandbox**, **Alpha**, **Beta** and **Alice**.
> - You can view the percentage of completed topic exercises in the course progress/exercise mode of the OffSec platform.
>
> - You can view the completion percentage of topic exercises for each topic by hovering the cursor over the exercise progress bar.

For this content, if you don't understand, you can **provide paid technical guidance**.



### exam

If you want to take the exam on Saturday and Sunday, it is recommended to **book one month in advance**, otherwise there will be only evening and early morning on working days, and pay attention to the time zone in which the exam time is located.

You need to prepare a camera, and an email will be sent to you before the exam to install a browser plug-in to monitor your screen.

The exam time is 24 hours, if you want to take a break for meals during the exam, you can type on the monitoring page to explain what you want to do.

After the exam, you need to write a [report](https://help.offensive-security.com/hc/en-us/articles/360046787731-PEN-200-Reporting-Requirements), so during the exam, you need to record the operation steps, screenshots, and flags (including IP addresses).

## Summary

- Be sure to do **information collection**.
- Don't make things too complicated.
- There are exp for machine utilization.

