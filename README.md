# impact


impact is an adversary ransomware simulator designed to replicate certain functionality often observed in groups such as BlackBasta, RansomHub, etc.

Specifically it implements the following features:
* Multi-threaded data encryption with file/directory exclusions based on real samples
* Intermittent encryption using AES or XChaCha20
    * Read 256 bytes, encrypt 64, etc - causes a file to become unusable without having to encrypt 100% of the contents
* Unique symmetric keys per file encrypted with RSA Public Key
    * Threat Actors would normally embed public key into binary - this program allows cmdline input for RSA file or generates on-the-fly
    * Private key is also generated to allow this program to decrypt
* Encrypted file extensions based on real-world examples
* Ransomware Note Content/Names based on group behaviors
* Optional capability to force-stop configured processes
* Optional capability to remove existing VSS Copies
* Capability to create 'dummy' data sets of specified size/file count for targeting rather than using pre-existing data
* Capability to adjust number of worker threads

Just a note that this does not perfectly emulate individual groups - for example, RansomHub is known to use ECC for protecting symmetric keys appended to data - for the sake of simplicity this only implements RSA but it wouldn't be hard to change this to ECC.

Every time that an encryption command is executed, a corresponding decryption command will be created in local file 'decryption_command.txt' - this command will provide instructions on how to reverse the encryption by specifying the appropriate cipher and RSA private key file.


### This tool is dangerous - I am not responsible if you completely brick, destroy, decimate, mangle or otherwise harm your data, devices or network in any way, shape or form.  You have been warned.

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