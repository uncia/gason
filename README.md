# gason
Automatically exported from code.google.com/p/gason
News
Update: 2013-12-16
Use Gason in new burp suite version: http://www.smeegesec.com/2013/02/sqlmap-plugin-for-burp-extender.html
Fix for running Gason in Windows: http://www.praetorian.com/blog/burp-sqlmap-plugin-for-windows
Old
This project contains a plugin to extend BurpSuite proxy. And know you can run gason stand alone!!
What's Gason?
This plugins are wrapper of well known security tools.

This tool was developed by Daniel García García a.k.a cr0hn.

Documentation
English: http://blog.buguroo.com/?p=2471&lang=en
Spanish: http://blog.buguroo.com/?p=2471&lang=es
Changelog
How to run?
From BurpSuite
You must copy the plugin at home of burpsuite are installed. Then write:

java -classpath gason-x.x.x.jar:"burpsuite_VERSION.jar" burp.StartBurp

Stand alone
You only need to write:

java -jar gason-x.x.x.jar

Some images
New stand alone interface:



Burpsuite integration:



SQLMap interface:



Integrated searcher:

