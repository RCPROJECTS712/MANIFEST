MANIFEST - live process triage
==============================

WHAT IT IS
----------
A live process monitor that labels every running process so you can actually
read your machine instead of squinting at Task Manager:

    CORE  (red)    Essential to Windows. Locked - the tool won't end it,
                   because doing so crashes your session. This includes
                   Windows Defender and the shared web component
                   (msedgewebview2) that powers Start-menu Search & Widgets.
    HW    (cyan)   Hardware / driver services - audio, graphics, bluetooth,
                   your wireless keyboard. Ending these can disable that
                   hardware until you reboot.
    OEM   (amber)  Manufacturer add-ons (Lenovo Vantage, FaceBeautify, Smart
                   Meeting, etc). Safe to close.
    YOU   (green)  Software you installed or opened (Brave, Mullvad,
                   Malwarebytes, this tool...).
    ??    (white)  Unclassified. Investigate before trusting.


THE HONEST PART
---------------
There is no state where Windows runs on 5 processes. The CORE items ARE the
minimum an OS needs. What this tool does instead: click SHOW ONLY OPTIONAL and
every essential process disappears from the view, leaving just the stuff that
is actually optional plus whatever you launched. That is your "clean unless I
fill it myself."


HOW TO RUN
----------
Double-click run.bat  (needs Python from python.org, "Add to PATH" ticked).
Or from a terminal:  python manifest.py


BUTTONS
-------
SHOW ONLY OPTIONAL  Hide CORE + HW; show only OEM / YOU / ??.
SHOW ALL            Bring everything back.
Category checkboxes Toggle any single category on/off.
Column headers      Click to sort (click again to reverse).

END PROCESS         Kill the selected process. Disabled for CORE. If a kill
                    is "Access denied", the process runs as SYSTEM - relaunch
                    MANIFEST as administrator (right-click run.bat > Run as
                    administrator).
FILE LOCATION       Open Explorer at the process's .exe.
VERIFY SIGNATURE    Authenticode check - "Valid" + a Microsoft/vendor signer
                    means genuine. Great for vetting an unknown process.
COPY PID            Copy the process ID.
STARTUP MANAGER     Opens Windows' Startup Apps. This is the REAL way to get a
                    quieter boot: stop things launching in the first place,
                    rather than killing them every session.
AUTO-REFRESH        On by default, updates every 3 seconds. Toggle off to
                    freeze the view.


TUNING IT
---------
Open manifest.py and edit the CLASSIFICATION section near the top. Add your own
software's process names to the YOU set, move things between CORE / HW / OEM as
you see fit. It's plain Python, no dependencies.

Note: ending an OEM process here only closes it for now - it will come back
next boot unless you disable it in STARTUP MANAGER or uninstall it.
