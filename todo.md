# features

- [ ] offer to copy the nmap and gowhitness command to clipboard
- [ ] tagging feature to mark hosts, services and ports as done

- [ ] query feature to filter hosts, services and ports by:
  - up/down status (e.g. `up:80/tcp`, `down:443/tcp`)
  - tags (e.g. `tag:done`)
  - service (e.g. `service:nginx`, `service:mysql`)

- [x] up filter should consider systems with open ports like the export does.
  - special case: depending on how the nmap scan was run, the up status from nmap has a different weight. when -Pn was used, all hosts are considered up, so the up filter should not consider those hosts as up. when -Pn was not used, the up filter should consider those hosts as up. hosts are always up if they have at least one open port, regardless of how the nmap scan was run. this filter should be applied to both the interactive views and the export.
- [ ] allow the user to specify multiple directories for the nmap subcommand. `seek nmap dir1 dir2 dir3` should scan all three directories and merge the results into a single view.


# bugs

- [x] the port lists cannot be filtered by open/closed status of the port. i would expect `u` to behave similarily to how it filters hosts by up/down status, but it does not.
- [ ] change `q` from quitting the application to behave the same way as `Esc` does. `q` should not quit the application, but instead return to the previous view or exit the current view. only if the user is in the main view and there is no previous view to return to, should `q` quit the application. alternatively, `Ctrl+c` or `Ctrl+q` should be used to quit the application entirely.
- [ ] fix scrolling in detail view
