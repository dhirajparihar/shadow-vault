# VHS Tape configuration for shadow-vault
# To run with Charmbracelet VHS:
#   vhs assets/demo.tape

Output assets/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 960
Set Height 600
Set Padding 20
Set WindowBar Colorful
Set WindowBarSize 38
Set Theme "Catppuccin Mocha"

Type "python examples/demo_agent_roundtrip.py"
Sleep 400ms
Enter

Sleep 9s
