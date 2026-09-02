- external tool features become available if the tool is installed and available in the system path
  - trigger nmap scans directly from within the app → scan exported lists with `nmap -iL` 
  - gowhitness integration → export a list of URLs for gowhitness to screenshot
  - read gowhitness files and add the collected information to the overview
- integrate with project-tools

---

the app should integrate with nmap. it should be able to trigger nmap scans directly from within the app. here is a description of the workflow:

- when the app is started, it should check if nmap is installed and available in the system path. if nmap is available, the nmap integration feature should be enabled and indicated in the UI through a visual cue (e.g., an icon). if not it stays disabled and the indicator should reflect that (e.g., a greyed-out icon).
- if there are no existing nmap scans in the directory, there should be an editor like interface where the user can enter urls or ip addresses to scan. here the scope is defined by the user. if there are existing nmap scans, the app will not change its behaviour from the existing workflow and will not show the editor interface. triggering a scan should then be done via the export functionality. this is described in a later section.
- for a defined scope, the user can select an nmap scan type from a list of predefined options. every type is linked to a command preset. after selection, this command is presented to the user in a text field where it can be modified before execution. the user can then start the scan after a double confirmation, where the full scope and command can be reviewed.
- nmap scans should be executed in a separate thread to avoid blocking the main application. the output of the scan should be captured and displayed in real-time within a live log tab. the user should be able to pause, resume, or cancel the scan at any time. If the scan is completed successfully, the results should be saved just as they would be if the scan was run externally.
- scan results are then parsed and added to the overview. The app should provide a summary of the scan results. the summary can be toggled between a condensed overview (e.g., number of hosts and ports discovered, which new ports were found), a diff where only new information is listed and a raw output view where the full nmap output is displayed.
- when previous scan results are available the existing export functionality already allows the user to export hosts, urls and ports. this is currently used to manually export information and run nmap scans externally. the app should provide an option in the export dialog to trigger an nmap scan directly from the app.

the preset nmap commands should be defined in a configuration file. the app should provide a default configuration file with a set of predefined commands. during the development i will provide my documentation, which contains a list of nmap commands that i use regularly. this will be used to create the default configuration file. 

if additional information or decisions are required, prompt me to provide them. for the tui design, use the tui-design skill.