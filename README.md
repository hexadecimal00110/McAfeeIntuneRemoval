# McAfee Intune Removal

Intune Proactive Remediation PowerShell scripts to remove McAfee consumer AV Products and ensure Defender for Endpoint can activate.

I'm not a professional Dev -- I try to improve where I can and leave comments behind in my code for future me to follow.




1. Place the MCPR.zip file somewhere accessible on the web -- I used a public Azure Storage Container as a static website to simply invoke-webrequest and download

2. Update line 162 in 'Remove-mcafee.ps1' with your URL

3. MCPR.zip is the MCPR tool extracted and packaged with a custom batch script -- this batch script calls the MCPR tool without the GUI - found this step online https://christianlehrer.com/?p=359

4. 'Detect-mcafee.ps1' and 'remove-mcpr.ps1' both use a function 'get-installedapplications' which I also found online - https://xkln.net/blog/please-stop-using-win32product-to-find-installed-software-alternatives-inside/

5. 'Remove-mcpr.ps1' uses the Intune Script Template from Oliver Kieselbach - https://github.com/okieselbach/Intune/blob/master/ManagementExtension-Samples/IntunePSTemplate.ps1

6. First - Script will detect installed apps using the function

7. Second - Remediation script does several things
    A. - Downloads and runs MCPR.zip removal
    B. - Uses 'get-installedapplications' function to call the msiexec /uninstall value for any remaining apps
    C. - Removes the Pre-Packaged "McAfee Personal Security" applet from AppX System Image
    D. - Removes the actual AppX "McAfee Personal Security" App after removal from system image 
    E. - Removes any traces of McAfee from the "WMI SecurityCenter2" database --- This is important to ensure that Defender for Endpoint re-enables itself



