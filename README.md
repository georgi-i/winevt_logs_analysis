## Winevt logs analysis (Remote connections)

### Simple script for the purpose of finding remote connections to Windows machine and ideally some public IPs. It checks for some EventIDs regarding remote logins and sessions.

You should **pip install -r requirements.txt** so the script can work and parse some of the .evtx files inside winevt folder.

The **winevt/Logs** folders and the script must have identical file path.

##### Execution Example #####

![Image of Spreadsheet](https://github.com/georgi-i/winevt_logs_analysis/blob/main/search.png)

##### Result Example #####

![Image of Spreadsheet](https://github.com/georgi-i/winevt_logs_analysis/blob/main/result.png)
