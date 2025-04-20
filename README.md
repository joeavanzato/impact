# impact

### This tool is dangerous - misuse can lead to irreversible consequences for your data and systems.  Use responsibly.

### impact is designed to help blue-teams test their defenses against ransomware through a controlled mechanism as well as provide a means to reverse any impact with built-in decryption capabilities.

impact is an adversary ransomware simulator designed to replicate certain functionality often observed in groups such as BlackBasta, RansomHub, etc.

If you want to truly test your ransomware detection and prevention capabilities, impact will give you the capability to do so using real-world observations.

Features:
* Multi-threaded data encryption with file/directory exclusions/inclusions based on real-world observations
* Intermittent percent-based encryption using AES or XChaCha20 with configurable percentage
* Unique symmetric keys per file to avoid known-plaintext analysis attacks
* Ransomware file extensions and behaviors based on real-world group observations
* Ransomware Note Content/Names based on real-world group observations
* Capability to force-kill commonly targeted processes
* Capability to remove existing VSS Copies
* Capability to create 'dummy' data sets of specified size/file count for targeting rather than using pre-existing data
* Capability to adjust number of encryption/decryption routines (concurrency)
* Ability to execute ransomware 'inline' or 'outline' - meaning either writing over the same file or writing to a new file and deleting the original
* Encrypted configuration data embedded into the executable
* Ability to delay ransomware note creation to avoid static detection signatures
* Can target specific directories or enumerate local/network drives to target

Just a note that this does not perfectly emulate all the TTPs/Behaviors of any given group - but it is good enough as a 
simulation in my experience.

Most encryption schemes for ransomware involve the generation of a unique symmetric key on a per-file basis - after 
the file is encrypted, an embedded public key is then used to encrypt the symmetric key (along with other data 
sometimes such as percent encrypted, original file-size, etc) and this additional encrypted data is appended to the end of each file.

The exact data varies per group - impact uses a generic implementation across all groups - the main differentiators between groups in the impact implementation are as follows:
* Ransomware Extension[s]
* Extension Editing Differences - Mutate vs Append
* Ransomware Note Name[s]
* Ransomware Note Content
* Symmetric Cipher Utilized
* Asymmetric Cipher Utilized
* Ransomware Note Behavior - Delayed or Immediate

Thus, the implementation remains the same between groups in this tool and it is mainly the metadata that presents a difference.

Every time that an encryption command is executed, a corresponding decryption command will be created in local file 'decryption_command.txt' - this command will provide instructions on how to reverse the encryption by specifying the appropriate reversed command-line arguments.

In general, the logic flow is as below:
1. From target directory, files are scanned to determine whether they shoudl be encrypted
   2. Based on specified inclusions/exclusions in embedded config file
3. For each file, first we generate a random symmetric key for AES/XChaCha20
4. If file size is less than our threshold, we encrypt the entire file
   5. Can be configured via -threshold parameter (in bytes)
6. If file is larger than the threshold, we retrieve our percent-based encryption parameter
   7. Calculate chunks of original file to encrypt and attempt to get as close to the desired percent as possible
8. Once complete, we generate a data structure to append to the end of the file and encrypt this structure with our embedded public RSA/ECC key
   9. Following this, we also embed two more data structures representing the length of our encrypted metadata and an encryption signature
10. After completing all file writes, we then either append our extension or mutate the existing extension depending on methodology of the group

### Groups Currently Implemented
* BlackBasta
* RansomHub
* Play
* Royal


### Command Examples
```shell
impact -directory \\localhost\C$\test -group blackbasta -recursive -create -create_files 10000 -create_size 5000
# Create 10,000 files with a target size of 5,000 Megabytes in the target directory then encrypt those files recursively
# When using -create, impact will ONLY target files created during this execution and nothing else
###
impact -directory \\localhost\C$\test -group ransomhub -recursive
# Encrypt the target directory recursively using notes, note-names, file extensions and symmetric encryption synonymous with the RansomHub group

impact -directory \\localhost\C$\test -group ransomhub -recursive -cipher xchacha20
# Same as above, but force the use of a specific cipher (defaults to group configuration)

impact -directory \\localhost\C$\test -group ransomhub -recursive -cipher xchacha20 -rsa_public "rsa_public.key"
# Same as above, but force the use of a specific public key for encryption (defaults to internally embedded key)

impact -directory \\localhost\C$\test -group ransomhub -recursive -cipher xchacha20 -rsa_public "rsa_public.key" -workers 100
# Same as above, but increase concurrency (default 25 threads)

impact -directory \\localhost\C$\test -group ransomhub -recursive -cipher xchacha20 -rsa_public "rsa_public.key" -workers 100 -ep 75
# Same as above, but increase how much the percentage of a file that gets encrypted (default 25%)

impact -directory \\localhost\C$\test -group ransomhub -recursive -cipher xchacha20 -rsa_public "rsa_public.key" -workers 100 -ep 75 -threshold 2048
# Same as above, but increase the size threshold for automatically encrypting 100% of a file (default 1048 bytes)
```


### Arguments
```
  -cipher string
        Specify Symmetric Cipher for Encryption/Decryption
  -create bool
        Create a mixture of dummy-data files in the target directory for encryption targeting - when using this, only files created by impact will be targeted for encryption, regardless of existence
  -create_files int
        How many dummy-files to create (default 5000)
  -create_size int
        Size in megabytes of dummy-file data to target - distributed evenly across create_files count (default 5000)
  -decrypt bool
        Attempt to decrypt using specified options - must include RSA Private Key and Group Name OR Cipher Used
  -directory string
        Target Directory - can be UNC Path (\\localhost\C$\test) or Local (C:\test)
  -ecc_private string
        Specify ECC Private-Key File - must be specified with decrypt if asymmetric system is ECC
  -ecc_public string
        Specify ECC Public-Key File to use - if blank, will use embedded key
  -ep int
        Percentage of data to encrypt in each file over the 100%-auto threshold (default 25)
  -generate_keys
        If specified, will generate new RSA/ECC keys to use for encryption/decryption purposes
  -group string
        Specify a group to emulate - if none selected, will select one at random
  -killprocs bool
        Attempt to stop configured list of process binaries on the target machine prior to encryption
  -list bool
        List available groups to emulate
  -method string
        inline - Read File, Encrypt in Memory, Write Modifications to Disk; outline - Read File, Encrypt to New File, Delete Original (default "inline")
  -recursive bool
        Whether or not to encrypt all subdirs recursively or not
  -rsa_private string
        Specify RSA Private-Key File - must be specified with decrypt if asymmetric system is RSA
  -rsa_public string
        Specify RSA Public-Key File to use - if blank, will use embedded key
  -skipconfirm bool
        Skip Directory Confirmation Prompt (be careful!)
  -threshold int
        File size in bytes to automatically encrypt 100% of the contents if file Size <= provided number (default 1024)
  -vss bool
        Attempt to remove all VSS copies on the target host prior to encryption
  -workers int
        How many goroutines to use for encryption (default 25)
```

### Credits/Acknowledgements
* github.com/mxk/go-vss
  * LICENSE: MPL 2.0