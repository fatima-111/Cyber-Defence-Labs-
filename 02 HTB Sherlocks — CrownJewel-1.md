HTB Sherlocks — CrownJewel-1
# **Sherlock Scenario**

Forela’s domain controller is under attack. The Domain Administrator account is believed to be compromised, and it is suspected that the threat actor dumped the NTDS.dit database on the DC. We just received an alert of vssadmin being used on the DC, since this is not part of the routine schedule we have good reason to believe that the attacker abused this LOLBIN utility to get the Domain environment’s crown jewel. Perform some analysis on provided artifacts for a quick triage and if possible kick the attacker as early as possible.

We have been provided with the following event log files:

![](https://miro.medium.com/v2/resize:fit:1050/1*Sm98VMeleq5tWidg2MZsjw.png)

## 1. Microsoft-Windows-NTFS.evtx

- **Contains:** Logs related to the NTFS file system, such as file creation, deletion, modification, and errors related to file system operations.
- **Use Case:** Useful for investigating suspicious file activity, data tampering, or forensic analysis of file-level changes on Windows systems.

## 2. SECURITY.evtx

- **Contains:** Security-related events, including logon/logoff attempts, account management, privilege use, and policy changes.
- **Use Case:** Essential for tracking authentication events, identifying unauthorized access, monitoring privilege escalation, and auditing security-related changes.

## 3. SYSTEM.evtx

- **Contains:** System-level events, such as driver failures, hardware issues, system service status changes, and other core Windows operations.
- **Use Case:** Useful for diagnosing system stability problems, service starts/stops, device failures, and overall system health monitoring.

We have also been provided with the `$MFT` file.

# Brief Explanation: What is `$MFT`?

- **$MFT** stands for **Master File Table**.
- It is a core component of the NTFS file system used by Windows.
- The `$MFT` contains detailed records about every file and folder on the NTFS volume, including:
- File names
- Sizes
- Timestamps (creation, modification, access)
- Permissions and metadata
- Physical location of the data on disk

## Use Case:

- The `$MFT` is crucial for digital forensics and incident response because it allows investigators to track file activity, recover deleted files, and analyze changes even if files have been tampered with or removed.

Lets start with the questions

**Question 1 — Attackers can abuse the vssadmin utility to create volume shadow snapshots and then extract sensitive files like NTDS.dit to bypass security mechanisms. Identify the time when the Volume Shadow Copy service entered a running state.**

To answer this question, we need to analyze the security logs. We have a file named `security.evtx`, which contains Windows Security Event Logs. To parse and examine these logs, we’ll use **Chainsaw**, a powerful command-line tool designed for fast and flexible log analysis.

I’ll export the security log into JSON format using Chainsaw. The following command reads the `SYSTEM.evtx` file and saves the parsed results as `system.json`:

chainsaw dump SECURITY.evtx --json --output ./system.json

![](https://miro.medium.com/v2/resize:fit:1050/1*vZ90ampX7j5cbi-SHg9cpA.png)

Let’s list all the unique event IDs present in the log. We can use the following command:

 ```bash
jq '.[].Event.System.EventID' system.json  | sort | uniq
```

I asked ChatGPT for the event ID corresponding to “Volume Shadow Copy service entered a running state.”

![](https://miro.medium.com/v2/resize:fit:1050/1*5CsIUd37Zuz4LXL14K9RUw.png)

```bash
jq '.[] | {Provider: .Event.System.Provider_attributes.Name, EventID: .Event.System.EventID, Time:.Event.System.TimeCreated_attributes.SystemTime,param1: .Event.EventData.param1, param2: .Event.EventData.param2}' system.json | grep -B 10 -A 10 'Shadow'
```

Explaination of the command :

- **Extracts Key Fields:**
- `Provider`: The name of the event source (for example, "Service Control Manager").
- `EventID`: The unique identifier for the event (e.g., 7036).
- `Time`: The timestamp of when the event occurred.
- `param1` and `param2`: Additional event data fields that may contain information about the specific service or action.
- **Filters for ‘Shadow’:**  
    After extracting the relevant details, the output is piped to `grep` to search for the keyword "Shadow."  
    The `-B 10 -A 10` flags tell `grep` to show 10 lines **before** and **after** each match, providing useful context around each relevant log entry.

![](https://miro.medium.com/v2/resize:fit:1050/1*q2EF0RClMcygaENUb-9Sug.png)

**Answer :2024–05–14 03:42:16**

**Question 2: When a volume shadow snapshot is created, the Volume shadow copy service validates the privileges using the Machine account and enumerates User groups. Find the two user groups the volume shadow copy process queries and the machine account that did it.**

**What does this question want you to find?**

When a **volume shadow snapshot** is created in Windows, the **Volume Shadow Copy service** (`VSS`) performs certain checks and actions to make sure it has the right permissions to create the snapshot. This is a security measure to ensure that only authorized accounts and processes can perform such sensitive operations.

**What happens under the hood:**

- The **VSS service** runs using the **machine account** (for example, `DC01$` for a machine named `DC01`).
- As part of its operation, it queries and validates membership of certain **user groups** to ensure the account has enough privileges.
- Specifically, the service checks two important user groups:

1. **Administrators** — To confirm the account has administrative rights.
2. **Backup Operators** — To verify backup-related permissions, as shadow copy creation is similar to taking a backup.

**How you find this in logs:**

- In the event logs, you will see entries showing the machine account (like `DC01$`) querying or enumerating these user groups.
- This usually appears as log events where the account attempts to access or validate group memberships for `Administrators` and `Backup Operators`.

**Why is this important?**

- Spotting these events helps you identify which account was used to create the shadow copy and which user groups were checked.
- If an attacker is abusing the shadow copy service to access sensitive files, you’ll see their activity reflected here — especially if they’re using a machine account or a compromised admin account.
- This provides critical context for tracking attacker behavior and understanding the permissions they’re leveraging.

I asked chatGPT **Common Event IDs for Group Enumeration.**

![](https://miro.medium.com/v2/resize:fit:1050/1*vxEtxQYXMwf7Ea0Z-8HIvw.png)

```
jq '.[] | {  
  Provider: .Event.System.Provider_attributes.Name,  
  EventID: .Event.System.EventID,  
  Time: .Event.System.TimeCreated_attributes.SystemTime,  
  AccountName: .Event.EventData.SubjectUserName,  
  CallerProcessName: .Event.EventData.CallerProcessName,TargetUserName: .Event.EventData.TargetUserName  
}' security.json | grep '\"EventID\": 4799' -A 10 -B 10
```
Explanation of the command —

This command extracts key details — such as the provider, event ID, timestamp, account name, caller process name, and target user name — from each event in the parsed Windows Security log. It then filters the output to display all events with **Event ID 4799** (which indicates group membership enumeration), along with 10 lines of context before and after each match for easier analysis.

![](https://miro.medium.com/v2/resize:fit:1050/1*OCyVUWCkkG8N2cHwT0Wp_A.png)

Right here, we can clearly see that the service (`VSSVC.exe`) is querying the "Administrators" and "Backup Operators" groups. The account performing these actions is the machine account `DC01$`. This confirms that when a shadow copy is created, the Volume Shadow Copy service validates its privileges by enumerating these critical user groups.

**Answer: Administrators, Backup Operators, DC01$**

**Question 3 : Identify the Process ID (in Decimal) of the volume shadow copy service process.**

cat security.json  | grep  -i callerprocessid -A 20 -B 20

![](https://miro.medium.com/v2/resize:fit:1050/1*3bVxjGM5IhaLLj4F_uaNxg.png)

The key field to focus on here is `CallerProcessId`, as it tells us which process initiated the action recorded in this event.

```bash
jq '.[] | {                                                
  Provider: .Event.System.Provider_attributes.Name,  
  EventID: .Event.System.EventID,  
  Time: .Event.System.TimeCreated_attributes.SystemTime,  
  AccountName: .Event.EventData.SubjectUserName,  
  CallerProcessName: .Event.EventData.CallerProcessName,ProcessID: .Event.EventData.CallerProcessId,TargetUserName: .Event.EventData.TargetUserName  
}' security.json | grep '\"EventID\": 4799' -A 10 -B 10
```

![](https://miro.medium.com/v2/resize:fit:1050/1*3vKkbsgjBdQMVSPK07KtGA.png)

![](https://miro.medium.com/v2/resize:fit:1050/1*vV85wfT42kUMHGoxc1nIsg.png)

**Answer : 4496**

**Question 4 :Find the assigned Volume ID/GUID value to the Shadow copy snapshot when it was mounted.**

```bash
cat *.json| grep -i 'shadow'  -A 30 -B 30
```

This is the only value we have

![](https://miro.medium.com/v2/resize:fit:1050/1*OyVD_msjNH60s9ki3Vfcqg.png)

**Answer: {06c4a997-cca8–11ed-a90f-000c295644f9}**

**Question 5: Identify the full path of the dumped NTDS database on disk.**

```bash
chainsaw dump \$MFT --json  > mft.json
```
converts the NTFS Master File Table into JSON format, making it easy to search file records. This allows quick identification of the full path where the NTDS database was dumped on disk.

![](https://miro.medium.com/v2/resize:fit:1050/1*g_l3hhQA_c70OE5V5Tw4xA.png)

**Answer: C:\Users\Administrator\Documents\backup_sync_Dc\Ntds.dit**

**Question 6 — When was newly dumped ntds.dit created on disk?**

```bash
cat mft.json | grep 'Users/Administrator/Documents/backup_sync_dc/ntds.dit' -A 20 -B 20
```

![](https://miro.medium.com/v2/resize:fit:1050/1*eVAgTYxYQeYUoXwhh_8kjw.png)

**Answer: 2024–05–14 03:44:22**

**Question 7 — A registry hive was also dumped alongside the NTDS database. Which registry hive was dumped and what is its file size in bytes?**

![](https://miro.medium.com/v2/resize:fit:1050/1*8jcOGrVH5wbhZ3NKP9YIWg.png)

The `backup_sync_dc` folder contains the dumped `ntds.dit` file. Any files downloaded alongside `ntds.dit`, such as the registry hive, are likely stored in this same directory.

```bash
cat mft.json | grep 'backup_sync_dc' -A 20 -B 20
```

![](https://miro.medium.com/v2/resize:fit:1050/1*X0YoPEyv9RilE7R20JI97g.png)

**Answer: SYSTEM, 17563648**

