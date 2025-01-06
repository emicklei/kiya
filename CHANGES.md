# Changes

### v1.14.0

- Add PromptForCommandLine field to profile.

### v1.13.0

- Add AutoCopyEnabled field to profile.

### v1.12.5

- Security upgrades from Dependabot

### v1.12.4

- Use new AWS SDK v2

### v1.12.3

- Dependency upgrades and fixing changes

### v1.12.2

- Fixed AKV client

### v1.12.1

- Fixed AKV client

### v1.12.0

- Added backup option

### v1.11.4

- Fix an issue with azure client creation

### v1.11.3

- Upgrade dependencies, fix breaking changes

### v1.11.2

- Fixes reading password from Stdin on Windows

### v1.11.1

- Fixes overwrite of value in AWS

### v1.11.0

- Added support for Azure Key Vault (AKV)
- Added support for File on local disc

### v1.10.1

- fix aws listing (use recursive search)

### v1.10.0

- add AWS Parameter Store backend

### v1.9.0

- add Google Secret Manager backend

### v1.8.1

- fallback to list command if argument is not a known command.

## v1.8.0

- add list command

### v1.6.0

- refactored kiya so that it can be used as a library

### v1.5.0

- add "env" function for template command that reads OS environment values.

### v1.4.3

- fixes exit (1) on error (thanks to Frank Schroder)

### v1.4.1

- more logging when moving secrets from one to another profile

### v1.4.0

- add filter for list operation (thanks Tom Geurtsen)

### v1.3.5

- default generate character set is made URL encoding free
- after generate password copy it to clipboard
- do not log secrets if a command fails
- return with exit code 1 if kiya is aborted 
