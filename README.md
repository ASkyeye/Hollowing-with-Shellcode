# Hollowing-with-Shellcode
利用Process Hollowing技术进行shellcode注入

## Process Hollowing技术
该技术一般有两种形式：

1. Hollowing with EXE
2. Hollowing with Shellcode

`Hollowing with EXE`需要我们手动将一个EXE文件映射到内存，包括：文件头的映射、各个节的映射、重定位及修改寄存器值等操作，较为繁琐

`Hollowing with Shellcode`只需要我们找到最关键的程序入口点`AddressOfEntryPoint`后，将shellcode写入到该地址即可，无需考虑重定位及修改寄存器等操作

注：在填入shellcode前请先使用`0x31`对其进行异或，在函数`HollowingWithShellcode`中存在对shellcode的异或操作

## 参考项目、文章及视频

- 在壳技术中利用了Process Hollowing技术：[https://github.com/psbazx/PE_shell](https://github.com/psbazx/PE_shell)
- 分析了`Stuxnet Skeeyah Taidoor`等malware中使用的各种Process Hollowing技术的变种：[https://www.youtube.com/watch?v=9L9I1T5QDg4](https://www.youtube.com/watch?v=9L9I1T5QDg4)
- 十分详细地介绍了Process Hollowing技术的整个流程：[https://github.com/m0n0ph1/Process-Hollowing](https://github.com/m0n0ph1/Process-Hollowing)
- 利用动调的方式介绍了该技术：[https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations](https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations)
- 使用`C#`编写的十分简洁的`Hollowing with Shellcode`程序：[https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Shellcode%20Process%20Hollowing/Program.cs](https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Shellcode%20Process%20Hollowing/Program.cs)

