# WinPcap
>WinpCap是一个强大地网络开发库，可以实现许多功能：获取可用地网络适配器；获取指定适配器信息（比如名称和描述信息）；捕获指定网卡地数据封包；发送数据封包；过滤捕获的包以及获取特定包等。
>首先到 https://www.winpcap.org/install/default.htm 下载安装winpcap驱动和DLL组件
>然后到 https://www.winpcap.org/devel.htm 下载winpcap开发包，解压到指定目录，里面包含了Lib,Include,文档和示例程序。
>首先创建一个C++控制台程序，设置如下：
>1)在"Configuration Properties->C/C++->General"中，在Additional Include Directories加入Include路径
>2)在"Configuration Properties->Linker->General"中，在Additional Library Directories中加入winpcap库文件路径
>3)在"Configuration Properties->Linker->Input"中， 在Additional Dependencies 加入用到的两个winpcap库文件(wpcap.lib and Packet.lib)
>4)为了使用Winpcap的远程访问，必须在预处理器中加入HAVE_REMOTE
>参考链接：
>https://www.codeproject.com/Articles/30234/Introduction-to-the-WinPcap-Networking-Libraries
