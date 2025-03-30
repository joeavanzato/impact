# impact

## This tool is dangerous - misuse can lead to irreversible consequences for your data/systems.  Use responsibly.

### This tool is designed to help blue-teams and sysadmins test their defenses against ransomware in a controlled environment and provide a means to easily reverse any impact with built-in decryption capabilities.

impact is an adversary ransomware simulator designed to replicate certain functionality often observed in groups such as BlackBasta, RansomHub, etc.

If you want to truly test your ransomware detection and prevention capabilities, impact will give you the capability to do using real-world observations.

Specifically it implements the following features:
* Multi-threaded data encryption with file/directory exclusions/inclusions based on real-world observations
* Intermittent percent-based encryption using AES or XChaCha20 with configurable parameters
* Unique symmetric keys per file to avoid ciphertext-analysis style attacks
* Encrypted file extensions based on real-world group observations
* Ransomware Note Content/Names based on real-world group observations
* Optional capability to force-kill commonly targeted processes
* Optional capability to remove existing VSS Copies
* Capability to create 'dummy' data sets of specified size/file count for targeting rather than using pre-existing data
* Capability to adjust number of encryption/decryption routines (concurrency)

Just a note that this does not perfectly emulate all the TTPs/Behaviors of any given group - but it is good enough as a 
simulation in my experience.

Most encryption schemes for ransomware involve the generation of a unique symmetric key on a per-file basis - after 
the file is encrypted, an embedded public key is then used to encrypt the symmetric key (along with other data 
sometimes such as percent encrypted, original file-size, etc) and this additional encrypted data is appended to the end of each file.

The exact data varies per group - impact uses a generic implementation across all groups - the main differentiators between groups in the impact implementation are as follows:
* Ransomware Extension
* Ransomware Note Name
* Ransomware Note Content
* Symmetric Cipher
* Asymmetric Cipher

Thus, the implementation remains the same between groups in this tool and it is mainly the metadata that presents a difference.

Every time that an encryption command is executed, a corresponding decryption command will be created in local file 'decryption_command.txt' - this command will provide instructions on how to reverse the encryption by specifying the appropriate reversed command-line arguments.

### Command Examples
```shell
impact -directory \\localhost\C$\test -group blackbasta -recursive -create -create_files 10000 -create_size 5000
# Create 10,000 files with a target size of 5,000 Megabytes in the target directory then encrypt those files recursively
# When using -create, impact will ONLY target files created during this execution and nothing else
###
impact -directory \\localhost\C$\test -group ransomhub -recursive
# Encrypt the target directory recursively using notes, note-names, file extensions and symmetric encryption synonymous with the RansomHub group


```

### Arguments
```
  -cipher string
        Specify Symmetric Cipher for Encryption/Decryption
  -create
        Create a mixture of dummy-data files in the target directory for encryption targeting - when using this, only files created by impact will be targeted for encryption, regardless of existence
  -create_files int
        How many dummy-files to create (default 5000)
  -create_size int
        Size in megabytes of dummy-file data to target - distributed evenly across create_files count (default 5000)
  -decrypt
        Attempt to decrypt using specified options - must include RSA Private Key and Group Name OR Cipher Used
  -directory string
        Target Directory - can be UNC Path (\\localhost\C$\test) or Local (C:\test)
  -group string
        Specify a group to emulate - if none selected, will select one at random
  -list
        List available groups to emulate
  -method string
        inline - Read File, Encrypt in Memory, Write Modifications to Disk; outline - Read File, Encrypt to New File, Delete Original (default "inline")
  -recursive
        Whether or not to encrypt all subdirs recursively or not
  -rsa_private string
        Specify RSA Private-Key File - if none, will generate and write to file
  -rsa_public string
        Specify RSA Public-Key File - if none, will generate and write to file
  -skipconfirm
        Skip Directory Confirmation Prompt (be careful!)
  -workers int
        How many goroutines to use for encryption (default 25)
```