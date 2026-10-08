# WiFi Lab desktop design

The governing surface is the native Qt application in `app/ui/main_window.py` and `app/ui/lab_workspace.py`. Shared visual tokens are owned by `app/ui/theme.py`.

The workspace uses a deep navy navigation rail, dark instrument panels and a cyan signal accent. Small gradients and cyan shadow effects reinforce the futuristic lab-console tone without animating the entire surface. Network inventory is the initial page. A persistent project selector establishes context for captures and recovery.

Native Qt buttons, tables, combo boxes, dialogs and form labels preserve keyboard behavior. Focus is visible, inputs have accessible names, disabled controls have contextual explanations, and errors remain beside the relevant action. Artifact evidence is adjacent to the capture list. Recovery results are revealed deliberately in a separate dialog.

The skills `baseline-ui`, `improve-ui` and `fixing-accessibility` were installed from https://github.com/ibelick/ui-skills. Implementation applies baseline-ui and the relevant accessibility guidance to the existing Qt primitives. React/Tailwind-specific instructions do not govern this Python application; improve-ui is an audit/planning skill and was not used to replace the user's requested implementation with a plan-only deliverable.

Capture/import/analysis/recovery states reflect actual tool outcomes. Synthetic inventory is labeled and cannot start real laboratory jobs. A PMKID or HCX-converted EAPOL record is distinguished from merely observing EAPOL messages.
