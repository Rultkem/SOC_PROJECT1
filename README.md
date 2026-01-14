# SOC_PROJECT1
The project is now finished. 
Project is made in pure bash.

Code collects suspicious IPs from ssh and network logs, and adds context to them through country in form of GeoIP, and then through reputation score gives a final verdict of risk of the ip from the logs. If risk is high the ip is autblocked, this action is also logged so it is noticed and can eaily be undone. An email is sent to the soc team of the high risk ip with ip and info as the subject. The result is also saved as a CSV file, to enable further analysis accross different platforms.


