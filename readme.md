Signatures/offsets tested on 22H2

A kernel mode driver designed for manual mapping with the ability to
- Filter NTFS journal entries from being read
- Remove strings from CSRSS
- Protect a process from having a handle opened to it

Create an issue if theres another method to be patched that requires kernel mode 

User mode implemented [here](https://github.com/w451/EchoDisablerUM)
