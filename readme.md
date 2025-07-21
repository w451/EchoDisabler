Signatures/offsets tested on 22H2

A kernel mode driver designed for manual mapping with the ability to
- Filter NTFS journal entries from being read
- Remove strings from CSRSS
- Protect a process from having a handle opened to it

Can be mapped via KDMapper

User mode implemented [here](https://github.com/w451/EchoDisablerUM)
