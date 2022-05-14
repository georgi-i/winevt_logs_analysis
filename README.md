## Winevt logs analysis

### Script for automating partial analysis of winevt folder containing .evtx logs from Windows OS

Simple script for the purpose of analysis. It checks for some EventIDs regarding remote logins and sessions on the machine.

You should **pip install -r requirements.txt** so the script can work and parse some of the .evtx files inside winevt folder.

The **winevt/Logs** folders and the script must have identical file path.

##### Execution Example #####

![Image of Spreadsheet](https://github.com/georgi-i/winevt_logs_analysis/blob/main/search.png)

##### Result Example #####

![Image of Spreadsheet](https://github.com/georgi-i/winevt_logs_analysis/blob/main/result.png)
