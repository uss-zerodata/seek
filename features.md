- external tool features become available if the tool is installed and available in the system path
  - trigger nmap scans directly from within the app → scan exported lists with `nmap -iL` 
  - gowhitness integration → export a list of URLs for gowhitness to screenshot
  - read gowhitness files and add the collected information to the overview
- integrate with project-tools

---

# Nmap Integration

the app should integrate with nmap. it should be able to trigger nmap scans directly from within the app. here is a description of the workflow:

- when the app is started, it should check if nmap is installed and available in the system path. if nmap is available, the nmap integration feature should be enabled and indicated in the UI through a visual cue (e.g., an icon). if not it stays disabled and the indicator should reflect that (e.g., a greyed-out icon).
- if there are no existing nmap scans in the directory, there should be an editor like interface where the user can enter urls or ip addresses to scan. here the scope is defined by the user. if there are existing nmap scans, the app will not change its behaviour from the existing workflow and will not show the editor interface. triggering a scan should then be done via the export functionality. this is described in a later section.
- for a defined scope, the user can select an nmap scan type from a list of predefined options. every type is linked to a command preset. after selection, this command is presented to the user in a text field where it can be modified before execution. the user can then start the scan after a double confirmation, where the full scope and command can be reviewed.
- nmap scans should be executed in a separate thread to avoid blocking the main application. the output of the scan should be captured and displayed in real-time within a live log tab. the user should be able to pause, resume, or cancel the scan at any time. If the scan is completed successfully, the results should be saved just as they would be if the scan was run externally.
- scan results are then parsed and added to the overview. The app should provide a summary of the scan results. the summary can be toggled between a condensed overview (e.g., number of hosts and ports discovered, which new ports were found), a diff where only new information is listed and a raw output view where the full nmap output is displayed.
- when previous scan results are available the existing export functionality already allows the user to export hosts, urls and ports. this is currently used to manually export information and run nmap scans externally. the app should provide an option in the export dialog to trigger an nmap scan directly from the app.

the preset nmap commands should be defined in a configuration file. the app should provide a default configuration file with a set of predefined commands. during the development i will provide my documentation, which contains a list of nmap commands that i use regularly. this will be used to create the default configuration file. 

if additional information or decisions are required, prompt me to provide them. for the tui design, use the tui-design skill.

---

# Detail View

please remap the "d" hotkey to open the detail view in a bigger view instead of collapsing it. this bigger view should also support searching the output for specific details. this will be a handy analysis tool across the app but especially when reading the raw nmap output in the scans tab.
you could add collapsing it to "D".

---

# Gowhitness Integration

the app should integrate with gowhitness. it should be able to export a list of urls for gowhitness to screenshot and read the gowhitness output files to add the collected information to the overview. here is a description of the workflow:

- when the app is started, it should check if gowhitness is installed and available in the system path. if gowhitness is available, the gowhitness integration feature should be enabled and indicated in the UI through a visual cue (e.g., an icon). if not it stays disabled and the indicator should reflect that (e.g., a greyed-out icon).
- similar to nmap scanning, the app should provide an option in the export dialog to trigger a gowhitness scan directly from the app. the user should be able to select a list of urls to export for gowhitness to screenshot.
- the active scan is shown in the scans tab. the user should be able to cancel the scan at any time. if the scan is completed successfully, the results should be saved just as they would be if the scan was run externally through the gowhitness command line interface, but in its own "gowhitness" subdirectory.

gowhitness can be either run directly from the command line if installed or through a docker container. the following commands have been used before:

~~~bash
# scan a list of urls from a file and write the results to a database
docker run --rm -v "$(pwd)":/data -v "$(pwd)":/fh  ghcr.io/sensepost/gowitness gowitness scan file -f /fh/dns.txt --write-db -D

# start a webserver to view the results in a browser 
docker run --rm --network=host -v "$(pwd)":/data ghcr.io/sensepost/gowitness gowitness report server --host 127.0.0.1 --port 7171
~~~

if test data is required, you can run gowhitness scans on the following urls and ip ranges. the associated nmap scans can be found in the ./test_scans directory, which serves as a work directory during development.

~~~txt
gbv-metten.de
hektor.cc
sso.hektor.cc
gps.hektor.cc
share.hektor.cc
notify.hektor.cc
alpha.hektor.cc
beta.hektor.cc
gamma.hektor.cc
10.10.10.0/24
~~~

if additional information or decisions are required, prompt me to provide them. for the tui design, use the tui-design skill.

---

# Gowhitness Output Parsing

the gowhitness output is stored in a sqlite database. the app should read this database and add the collected information to the detail view of a host, service or related port.

- indicate if a screenshot is available for a specific url in the detail view. if a screenshot is available, provide an option to open the screenshot in the default image viewer.
- if it is possible to identify the system and underlying technology, display this information in the detail view. gowhitness already tries to identify some technologies. system names are often included in the title of the page.
- list headers and other metadata collected by gowhitness in the detail view. this information should be displayed in a structured format, similar to how nmap output is displayed.
- when the gowhitness report server is available, provide an option to open the element in the browser. this should open the report server in the default browser and navigate to the specific element.
