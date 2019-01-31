# Collect-Server-Attributes
Given a list of server names in CSV format as input, this will create
a report in CSV format of attributes for the input servers.  The input
CSV must have a column header literal of "Hostname".
## Example
```powershell
Collect-Server-Attributes c:\serverList.csv c:\report.csv
```