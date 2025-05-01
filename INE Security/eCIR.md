Preparation :
1- a skilled IR team
2- security awareness and training
3- good police
4- Breach and incident plan
5-maintaining a chain of custody
6- tools ( EDR - siem - etc ....)
7- IH starter kit ( software and hardware )


categorize network to :
Network perimeter ( DMZ , NIPS )
host perimeter ( HIPS )
host level ( AV n EDR )
application level ( app logs )

[search] win network tools : netstat , lsof


containment : 
1- short term containment
2- system back-up
3- long term containment

incident management tools : RTIR

incident handling forms :
1- incident contact list ( all team from 0 to ceo )
2-incident detection ( first person and summary of incident )
3- incident casualties ( system details and date&time)
4- incident containment 
5- incident eradication


# windows cheat sheet

1- users accounts :

```
C:\Users\HP>net --help
The syntax of this command is:

NET
    [ ACCOUNTS | COMPUTER | CONFIG | CONTINUE | FILE | GROUP | HELP |
      HELPMSG | LOCALGROUP | PAUSE | SESSION | SHARE | START |
      STATISTICS | STOP | TIME | USE | USER | VIEW ]
```

2- Process :

```
C:\Users\HP>tasklist
C:\Users\HP>wmic process list full 
```

3- Services :

```
C:\Users\HP>net start
C:\Users\HP>sc query | more
C:\Users\HP>tasklist /svc
```

4- scheduled tasks 

```
C:\Users\HP>schtasks
```


5- Startup folders

The location of user Startup folders is:
C:\Users\ ….. \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\
The location of the ‘All users’ Startup folders is:
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\

**The registry run keys perform the same action, but can be located in four different locations:**

- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce

**The following Registry keys can be used to set startup folder items for persistence:**

- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders

**The following Registry keys can control automatic startup of services during boot:**

- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
- HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices

6- file shares :

```
C:\Users\HP>net view \\127.0.0.1
```

fireWall settings :

```
C:\Users\HP>netsh advfirewall show currentprofile
```

log entries :

```
C:\Users\system>wevtutil qe security
```

GUI tools :
lusrmgr.msc for user Accounts 
taskmgr.exe for Process
services.msc for Services
eventvwr.msc for log entries 

for Linux (useful investigation software)
Chkrookit
Tripwire / AIDE

GRR IR framework
Velociraptor IR framework [Learn](https://www.youtube.com/watch?v=EA40rztSOd4&t=62s&pp=ygUZVmVsb2NpcmFwdG9yIElSIGZyYW1ld29yaw%3D%3D)

