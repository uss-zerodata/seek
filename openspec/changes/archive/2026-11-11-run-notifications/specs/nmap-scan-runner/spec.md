## ADDED Requirements

### Requirement: Every scan dialog fits the terminal
The scope, preset, command and review dialogs SHALL never be wider or taller than the terminal. When their content does not fit, the long part (the scope, the preset list, the command, or the reviewed arguments) SHALL scroll within the dialog, and the choices and the line that names the keys SHALL stay on screen. A switch in a dialog SHALL show its state in characters, not by colour alone.

#### Scenario: Hundreds of targets on a small terminal
- **WHEN** the user reviews a scan of 300 addresses in an 80x24 or 60x18 terminal
- **THEN** every dialog of the flow fits the screen, the start choice and the key line are visible, and the command scrolls inside its own region

#### Scenario: A short command on a large terminal
- **WHEN** the review shows a command of three targets in a 120x40 terminal
- **THEN** the dialog is only as tall as its content

#### Scenario: The progress switch
- **WHEN** the progress switch is off, then on
- **THEN** it reads `[ ]`, then `[x]`
