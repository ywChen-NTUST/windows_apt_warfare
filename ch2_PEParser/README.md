# ch2 - PEParser

產生執行檔

```
make
```

執行範例

```
C:\Users\frank\Desktop\security\windows_apt_warfare\ch2_PEParser>PE-Parser.exe ..\msgbox\msgbox.exe
filename: ..\msgbox\msgbox.exe
filesize: 54631 bytes

---

DOS header start: 0x0
Signature: MZ

NT header start: 0x80
Signature: PE

File header start: 0x84
        Machine: AMD 64 (x64)
        Num of Sections: 15
        Compiled time: 2022-08-24 16:30:05 台北標準時間
        Symbol table addr: 0x6800
        Num of Symbols: 1201 (0x4b1)
        Size of Option header: 240 (0xf0)
        Charactistics:
                No base relocation
                Executable
                Line numbers removed (deprecated)
                2GB+ addresses handleable

Option header start: 0x98
        Image base: 0x400000
        Size of image: 73728 (0x12000)
        Size of headers: 1024 (0x400)
        Entrypoint: 0x4014e0
        Static alignment: 512 (0x200)
        Runtime alignment: 4096 (0x1000)
        Data Directory:
                Export directory                              0x00000000 ~ 0x00000000  (0x00000000)
                Import directory                              0x00008000 ~ 0x000087a0  (0x000007a0)
                Resource directory                            0x00000000 ~ 0x00000000  (0x00000000)
                Exception directory                           0x00005000 ~ 0x00005270  (0x00000270)
                Security directory                            0x00000000 ~ 0x00000000  (0x00000000)
                Base relocation table                         0x00000000 ~ 0x00000000  (0x00000000)
                Debug directory                               0x00000000 ~ 0x00000000  (0x00000000)
                x86 architecture specific data (deprecated)   0x00000000 ~ 0x00000000  (0x00000000)
                Global pointer directory index (deprecated)   0x00000000 ~ 0x00000000  (0x00000000)
                Thread local storage (TLS)                    0x00004040 ~ 0x00004068  (0x00000028)
                Load configure directory                      0x00000000 ~ 0x00000000  (0x00000000)
                Bound import directory in headers             0x00000000 ~ 0x00000000  (0x00000000)
                Import address table (IAT)                    0x000081f0 ~ 0x00008390  (0x000001a0)
                Delay load import descriptors                 0x00000000 ~ 0x00000000  (0x00000000)
                COM runtime descriptor                        0x00000000 ~ 0x00000000  (0x00000000)
                Reserved                                      0x00000000 ~ 0x00000000  (0x00000000)

Section header start: 0x188
        .text           Static: 0x00000400 ~ 0x00002200 (0x00001e00)     Dynamic: 0x00001000 ~ 0x00002ce8 (0x00001ce8)   R-X
        .data           Static: 0x00002200 ~ 0x00002400 (0x00000200)     Dynamic: 0x00003000 ~ 0x000030d0 (0x000000d0)   RW-
        .rdata          Static: 0x00002400 ~ 0x00002a00 (0x00000600)     Dynamic: 0x00004000 ~ 0x000044d0 (0x000004d0)   R--
        .pdata          Static: 0x00002a00 ~ 0x00002e00 (0x00000400)     Dynamic: 0x00005000 ~ 0x00005270 (0x00000270)   R--
        .xdata          Static: 0x00002e00 ~ 0x00003000 (0x00000200)     Dynamic: 0x00006000 ~ 0x000061f4 (0x000001f4)   R--
        .bss            Static: 0x00000000 ~ 0x00000000 (0x00000000)     Dynamic: 0x00007000 ~ 0x00007980 (0x00000980)   RW-
        .idata          Static: 0x00003000 ~ 0x00003800 (0x00000800)     Dynamic: 0x00008000 ~ 0x000087a0 (0x000007a0)   RW-
        .CRT            Static: 0x00003800 ~ 0x00003a00 (0x00000200)     Dynamic: 0x00009000 ~ 0x00009068 (0x00000068)   RW-
        .tls            Static: 0x00003a00 ~ 0x00003c00 (0x00000200)     Dynamic: 0x0000a000 ~ 0x0000a010 (0x00000010)   RW-
        /4              Static: 0x00003c00 ~ 0x00003e00 (0x00000200)     Dynamic: 0x0000b000 ~ 0x0000b050 (0x00000050)   R-- discardable
        /19             Static: 0x00003e00 ~ 0x00005e00 (0x00002000)     Dynamic: 0x0000c000 ~ 0x0000df08 (0x00001f08)   R-- discardable
        /31             Static: 0x00005e00 ~ 0x00006000 (0x00000200)     Dynamic: 0x0000e000 ~ 0x0000e149 (0x00000149)   R-- discardable
        /45             Static: 0x00006000 ~ 0x00006400 (0x00000400)     Dynamic: 0x0000f000 ~ 0x0000f222 (0x00000222)   R-- discardable
        /57             Static: 0x00006400 ~ 0x00006600 (0x00000200)     Dynamic: 0x00010000 ~ 0x00010048 (0x00000048)   R-- discardable
        /70             Static: 0x00006600 ~ 0x00006800 (0x00000200)     Dynamic: 0x00011000 ~ 0x0001109b (0x0000009b)   R-- discardable
```


