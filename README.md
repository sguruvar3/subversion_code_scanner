svn_codescanner
===============

Subversion code scanner

To detect potential security attacks such as phishing, cross site scripting (XSS) etc. by inspecting the code base [HTML, JavaScript?, XSL, Java, C....].

Reg-Ex based and is able to detect potential security attacks such as phishing, cross site scripting (XSS) etc. by inspecting any code base. The purpose of this Code scanner is to ensure no malicious content is injected into the content.

What is it used for
==================
The objective of the code scanner is to detect malicious attacks such as phishing and Cross Site Scripting attacks (XSS)
Phishing

When an URL is tweaked to go to some other fraudulent page, this attack happens. For ex. http://www.bankExample.com to   http://www.bankExampleS.com

For more info: http://en.wikipedia.org/wiki/Phishing
XSS

When injecting client side scripts, this attack happens

For more info: http://en.wikipedia.org/wiki/Cross-site_scripting
Epilog

This code scanner is able to detect these two kind of attacks     

Key Features
============

- Rule-set (XML based) is separated from the code base thus separation of concern is maintained

- Rules are based on Regular Expressions (Reg-Ex) thus larger pie of the attacks have been addressed

- Supports versioning control systems like SVN and can be extendable to any other Versioning systems

- Customizable to any level since it’s based on Rule-set matching pattern

- Reusable in any other projects which requires prevention from security attacks with less coding effort

- Able to detect even a single character change 
