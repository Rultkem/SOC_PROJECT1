# SOC_PROJECT1
The project is written in bash.
Searches through authentication logs and network logs, to see if any failed passwords attempts have happened and if so how many attempts from which ip. 
Then summarizes the result in a dashboard and adds a basic risk evaluation. 
Further an alerts.txt file is created containing the results as well as the MITRE ATT&amp;CK technique id of the detection. This can serve as a ticket to send to a response team.

In the future might add possible basic responses like blocking the suspicious ip directly when it is discovered so as not to wait for the response team and remediate the potential threat as quickly as possible thus minimizing response time and potential damage. And then the response team can do further analysis and evaluation of further responses later.

