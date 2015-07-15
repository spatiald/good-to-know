#!/bin/bash
#   xrandr
# You will see all your available resolutions. Now you go here. You will have to find the correct modeline for your monitor. For instance mine is: 148.35 1920 2008 2052 2200 1080 1084 1089 1125 +hsync +vsync
# Then type:
#   xrandr --newmode "1920x1080_60.00" 148.35 1920 2008 2052 2200 1080 1084 1089 1125 +hsync +vsync
#   xrandr --addmode CRT2 1920x1080_60.00
#   sudo nano /etc/gdm/PreSession/Default
#
# and add the following lines:
#   xrandr --newmode "1920x1080_60.00" 148.35 1920 2008 2052 2200 1080 1084 1089 1125 +hsync +vsync
#   xrandr --addmode CRT2 1920x1080_60.00
#
# Change the above modeline with the appropriate one. Also change the word CRT2 with your output.

xrandr --newmode  "1680x1050-VGA-0" 147.14 1680 1784 1968 2256 1050 1051 1054 1087 +hsync +vsync
xrandr --addmode VGA-0 1680x1050-VGA-0
