# RegBinaryToSD

RegBinaryToSD.exe parses data in a REG_BINARY registry value as a Security Descriptor.

Command-line syntax:
```
RegBinaryToSD.exe -k keypath [-v valuename] [-o objtype]

keypath   : Full path to a registry key, of the form "rootkey\subkey". Supported root keys
            include HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_USERS, and HKEY_CLASSES_ROOT.
            The root key portion can be its full name (e.g., "HKEY_LOCAL_MACHINE"),
            abbreviated (e.g., "HKLM"), or PowerShell drive format (e.g., "hklm:"). The
            key path is case-insensitive. The keypath must be quoted if it contains spaces,
            and should be quoted when executed in PowerShell if the keypath contains special
            characters such as parentheses or curly braces.

valuename : The name of a value in that key, usually a REG_BINARY value. The name must be
            quoted if it contains spaces. If -v is not specified, RegBinaryToSD.exe reads the
            key's default (unnamed) value.

objtype   : (Optional) An object type to translate permission names. Supported object types
            include "SDDL" and the following: file, dir, pipe, key, share, process, thread,
            service, scm, com, winsta, desktop, section, filemap, evt, token, and ntds.
            If objtype is "SDDL", RegBinaryToSD.exe outputs the security descriptor in Security
            Descriptor Definition Language format.

Examples:
  RegBinaryToSD.exe -k "HKCR\AppId\{00021401-0000-0000-C000-000000000046}" -v AccessPermission -o com
  RegBinaryToSD.exe -k HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity -v SrvsvcShareAdminConnect -o share
  RegBinaryToSD.exe -k HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CoreMessagingRegistrar\Security -v Security -o service
  RegBinaryToSD.exe -k HKEY_LOCAL_MACHINE\SECURITY\Policy\SecDesc
(That last example must be executed as LocalSystem.)
```

Provided as x64 (RegBinaryToSD.exe) and x86 (RegBinaryToSD32.exe) builds.