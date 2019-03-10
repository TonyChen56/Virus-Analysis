[TOC]

最近准备面试病毒分析岗，听大佬们说有的面试官会问是否分析过WannaCry，所以就准备分析分析永恒之蓝，一来方便自己面试，二来还能给自己刷经验。萌新第一次分析病毒，分析的不好各位大佬多多见谅啊~

# 样本概况

```
文件: C:\vir\wcry2.0\wcry2.0\wcry.exe
大小: 3514368 bytes
文件版本:6.1.7601.17514 (win7sp1_rtm.101119-1850)
修改时间: 2017年5月13日, 2:21:23
MD5: 84C82835A5D21BBCF75A61706D8AB549
SHA1: 5FF465AFAABCBF0150D1A3AB2C2E74F3A4426467
CRC32: 4022FCAA
```

# 查壳

首先使用PEiD和ExeInfo工具对样本进行查壳 以下是查壳结果

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0br3rmsdvj30c406qjrp.jpg)
![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0br3rpwqgj30f407h75g.jpg)

**结论：**病毒使用VC6编写的  无壳

# 基础分析

## 基础静态分析

### 查看字符串

首先在IDA中查看程序的字符串信息 看看能否得出某些信息![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0br4pc7mlj30te0e3ab6.jpg)

在IDA中看到字符串中含有RSA和AES 应该是和病毒加密方式相关 但具体的还需要再进一步确认

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0br4pc2bij30si0bw0to.jpg)

紧接着看到了这么一串字符串 关于cmd命令 大概是在引用某些参数 

字符串的部分就只有这么多信息 

### 使用PEiD识别加密算法

既然字符串中识别到了用于加密的标准库函数 那么在这里我使用PEID的Kyrpto ANALyzer插件扫描病毒程序  来识别加密算法 扫描结果如图所示

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0br66o7htj309k094dfu.jpg)

由上图可知 病毒使用了CRC32和AES加密算法 其中`CryptDecrypt`和`CryptDecrypt`是微软提供的用于一个用于加密的类库 而ZIP2和ZLIB是压缩算法

### 查看导入表

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0br6uo1kej30jz0acq5q.jpg)
![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0br6ur7zzj30li0bsaek.jpg)在`Kernel32`的导入函数里发现了 `LoadResource`  `LockResourse` `FindResourceA` 等函数 说明资源段里可能会大有文章 此处需要留意

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0br6urf8hj30ls0bt0xc.jpg)

接着 在`ADVAPI32.dll`里发现了注册表相关的操作  说明病毒对注册表进行了操作

### 查看资源段

接着查看病毒的资源段

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0br88on9lj30lz0flwfp.jpg)

最重要的就是这个资源名为XIA的自定义资源了 由于资源头是PK 所以猜测这应该是个ZIP压缩文件  接下来直接将资源提取

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0brbvuj8tj30ms0cugoo.jpg)

可以看到 上图就是提取出来的资源 这个就是病毒释放到桌面的一些文件了 但是具体是什么 需要进一步分析 

## 基础动态分析

### 查看进程树

首先使用`ProcessMonitor`查看一下进程树

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0brm5m5eej30tz04at8v.jpg)

由上图可以得知 病毒创建了四个子进程  其中还使用了`cmd.exe`执行一个批处理脚本文件 

### 注册表监控

关于注册表 这里我使用regshot对运行病毒前后做一个快照进行比对 直接查看结果

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0brn4010nj30w80dljsf.jpg)

关于注册表的修改操作并不多 在HKLM\SOFTWARE新增加了一个键 并且把当前病毒的路径添加上去 并且还添加了另外两个值

### 文件监控

接下来是文件的监控

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0brq10ptrj30ty0fnq5e.jpg)
![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0brqif3jlj30u80ftq5q.jpg)

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0brrlsy9wj30ug09jdh6.jpg)

图一： 病毒在系统的每一个目录下释放了`@WanaDecryptor@.exe` `@Please_Read_Me@.txt`的文件 这里应该是在感染文件了  

图二：在桌面目录下创建了一个`.bat`的批处理脚本 然而我在桌面上却没有看到这个脚本 应该是执行完之后被删除了  

图三：病毒在系统盘和桌面释放了几个PE文件并启动执行 这里应该是在释放隐藏在资源中的文件

### 网络监控

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0brsaavl9j30tz0fmq57.jpg)

从网络监控可以看到 病毒一直在监听两个端口 并尝试连接局域网内的一些ip 企图向局域网扩散

至此 基础的动态分析也就结束了

# 使用IDA和OD进行详细分析 

下面我们来对WannaCry的每一个函数进行逐个解析 以便搞清楚病毒所有的行为

## 对wcry.exe病毒主程序的分析

### 主体逻辑

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0brt70e3xj30up0diaam.jpg)

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0brt6w85wj30um0d2mxt.jpg)

以上是WannaCry的主体逻辑 但是这个并不是WannaCry的全部代码 只是一个傀儡exe而已 其中百分之九十的代码都是病毒的准备工作 下面将对所有的函数进行逐一分析

首先 我将其主体分为两个部分 **第一部分 初始化操作**  **第二部分 加载病毒核心操作** 

### 第一部分 初始化操作

首先来分析第一部分 也就是病毒的初始化操作 代码逻辑如下

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0brtwpaknj30xu0gtzl8.jpg)

#### GetRandom 获取随机数

首先来分析一下第一个未被IDA签名库识别的函数 我将他命令为GetRandom  函数主体如下

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0brufc6wwj30un0dwjrt.jpg)
![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bruy14szj30uw0dimxq.jpg)

病毒首先获取到计算机名 然后计算出计算机名的ASCII乘积 将这个乘积作为随机数种子 调用两次rand函数 最后获取到一个字母+数字的随机字符串

#### SetReg 设置注册表项

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0brvnxixdj30oj04maa5.jpg)

接下来程序对命令行参数做了一个判断 然后切换当前进程的路径为工作目录 之后来到第二个未被IDA识别的函数  函数主体逻辑如下

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0brw55fvnj30uq0d4wex.jpg)

病毒创建了一个注册表项 然后将当前的exe所在的绝对路径设置到到注册表的`\HKEY_LOCAL_MACHINE\SOFTWARE`下   但是在我的机器上设置失败了 因为这个注册表键的设置需要有管理员权限才能成功 

####  ReleaseFiles  释放资源文件

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0brxbl3p9j30q30esjru.jpg)

这个函数首先将资源中隐藏的压缩包进行解压 解压密码是WNcry@2017 然后释放压缩包中的所有文件到当前进程的路径下

释放完之后的桌面路径如下图所示 

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs0h2geej30d00fwth9.jpg)

其中msg文件夹下的是病毒用到的语言包 至于剩下的文件目前还不得而知

#### WriteCwnry   写入c.wnry

接下来分析`WriteCwnry`这个函数 函数主体如下

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs1hqztij30ta0dbdg9.jpg)

这个函数获取到了三个比特币账户 然后随机将其中的某一个写入到c.wnry文件中   所以c.wnry这个文件应该是跟勒索相关的

#### ExeCmdCommand 执行命令行参数

`ExeCmdCommand`这个函数执行了两次 主体如下

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs2jhghhj30sz0dudgb.jpg)

第一个`ExeCmdCommand`创建了一个进程 进程的参数是`attrib +h .` 这个参数的含义是将当前路径下的所有文件设置为隐藏 但是这其实是个错误的命令 正确的命令是`attrib +h` 没有后面的那个点  所以这个函数也就没有起到作用

第二个``ExeCmdCommand`直接看命令行参数  `'icacls . /grant Everyone:F /T /C /Q'` 这条命令是给当前的windows系统添加了一个叫`Everyone`的用户 并给这个用户所有的权限

至此 第一个部分分析完成

### 第二部分 加载病毒核心操作 

接下来分析第二部分 主体如下所示  这部分的函数所有的操作都只有一个目的 就是为了调用dll中的导出函数 接下来我们逐个进行分析

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs3mqgrej30sz09k74i.jpg)

#### GetApis 获取必要的API函数

GetApis的函数主体如下

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs46p312j30v00fwgmc.jpg)

这个函数的功能很简单 就是在获取各个API函数的地址  比如`CreateFileW`  `WriteFile` 等等 为后面的操作做准备

####  CDatabase::CDatabase 构造函数

接下来是这个对象的构造函数了

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs4phiaoj30pi09waa7.jpg)

也没有做什么实际的时候 初始化了两个用于线程同步的临界区对象

#### ImportKeyAndAllocMem 导入密钥并申请空间

接下来是`ImportKeyAndAllocMem`

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs55jfs1j30s80dq74m.jpg)

这个函数做了两件事情 1. 导入RSA的私钥 用于后面的解密文件 2. 申请两块大小为0x100000的内存 

#### DecryptFile 解密t.wnry

私钥已经导入完成 那么接下来要做的就是解密了 

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs5ummslj30uc0g3wfa.jpg)

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs6ex2ktj30ty0eh74l.jpg)

这个函数一直在对t.wnry这个文件进行读取操作 读取到内存之后传入上个函数拿到的密钥句柄 在内存中进行解密 然后返回解密之后的文件内容 我们可以在OD中查看函数的返回值

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs6yfiexj310j0f8tc5.jpg)

这里可以看到解密之后的内容 是一个PE文件 接下来提取出解密之后的文件内容 查看一下PE结构 判断是个dll文件 接下来再跟t.wnry原始文件做一个对比

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs7gb092j30oi0fdgrd.jpg)

大小值相差了0.2KB 那么可以判定t.wnry是个隐藏的dll文件

#### WriteAllocMem  拷贝PE文件到内存

解密完成之后 再看下一个函数`WriteAllocMem`

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs87dmshj30vg0fh755.jpg)

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs8kzqntj30tx0ett9b.jpg)

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs905vh4j30uw0fh74v.jpg)

这个函数的代码量比较多 但是总结起来 就做了两件事 1. 申请了一块堆空间 2.去掉了解密出的PE文件的DOS头以后 将整个PE文件拷贝到了堆空间中

#### GetExportFunAddr 获取导出函数地址

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bs9jxgthj30sx04kmx3.jpg)

这个函数传了两个参数 一个是堆空间的首地址 一个是`TaskStart`这个字符串  单步步过这个函数 可以看到函数返回了一个地址

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsa9otmwj310c0dtq6c.jpg)

并且在后面调用了这个这个地址 但是我们并不知道地址从何而来 所以还需要跟进去

函数主体如下

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsazewopj30ts0eqwf4.jpg)

这个函数首先取出了数据目录表 然后根据数据目录表找到了导出表 接着查看刚刚提取出来的dll的导出表 如下

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsbli4a3j30f808s0sq.jpg)

有一个导出函数`TaskStart` 这不就是传进去的第二个参数吗？

接着比对dll和调用返回地址的汇编代码 如下 

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsc0vjhgj311j0gz427.jpg)

#### 第二部分小结

第三部分分析完成 接下来做一个小结 总体行为如下

1. 获取必要的API函数地址
2. 导入私钥并申请空间
3. 用导入的私钥解密出一个dll
4. 申请一块堆空间 将dll写入到堆内存里
5. 在堆内存中找到dll的导出函数地址 并调用

从上面的分析可以得出病毒的主体程序实际上只做了一些初始化的操作 到目前为止并没有看到它感染或加密任何一个文件 也没有对用户进行勒索 真正的核心代码在t.wnry中   由于这个函数是在堆空间中调用 所以在IDA中并没有显示出伪C代码 那么接下来需要分析刚刚提取出来的dll

## 对t.wnry.dll(病毒核心部分)的分析

### 主体逻辑

主体逻辑如下 下面就是病毒的所有操作了 包括加密文件 勒索用户等所有操作

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bscpzwmuj30u20fgq3p.jpg)

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsczy1r1j30u80gmjs8.jpg)

### GetUsersidAndCmp 获取当前用户的SID并与系统的SID作比较

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsdb4azmj30s20dgdg7.jpg)

这个函数从注册表中获取到当前用户的SID并与系统的SID做比较 返回比较的结果

### CreatePkyAndEky 创建00000000.pky和00000000.eky 

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsdpbkn1j30sj0g7js0.jpg)

这个函数在桌面创建了00000000.pky和00000000.eky 这两个文件  其中00000000.pky是公钥 00000000.eky是加密后的私钥 我已经将未加密是私钥提取出来 如下

```C++
0018E584  07 02 00 00 00 A4 00 00 52 53 41 32 00 08 00 00  ...?.RSA2...
0018E594  01 00 01 00 73 F6 BE B8 C8 55 17 87 6A F8 0D 55  ..s鼍溉U噅?U
0018E5A4  CF FD 1A F8 1B 4B F4 17 FC 14 F4 D4 EE 25 DD C0  淆?K??粼?堇
0018E5B4  CD 0F A3 BB 63 32 AE 1D E3 47 34 2B CB D8 C5 FD  ?；c2?鉍4+素琵
0018E5C4  90 69 2F C1 F3 0B BD 91 CB E1 96 26 03 52 E3 9C  恑/馏綉酸?R銣
0018E5D4  D2 F0 89 1A 36 66 87 FC 75 09 63 05 75 44 37 AF  茵?6f圏u.cuD7?
0018E5E4  E0 44 85 87 10 CF 0A 5B 89 4C 91 45 90 69 7F F8  郉厙?[塋慐恑?
0018E5F4  31 58 35 31 2B 0C 8B D8 C6 85 16 C2 8D C4 C1 EF  1X51+.嬝茀聧牧?
0018E604  EF 10 10 1D ED AA 53 E6 79 65 83 2D 36 4B C8 68  ?愍S鎦e?6K萮
0018E614  DD AD 99 02 2D 18 87 BE CB 08 F9 23 A4 27 6E DA  莪?-嚲???n?
0018E624  BA C1 E9 14 55 FF 61 E8 41 54 08 07 AD F5 8F C8  毫?Ua鐰T徣
0018E634  FB 83 5D 87 5D 09 67 71 B2 9F 7B A5 C3 5C 23 2F  麅]嘳.gq矡{ッ\#/
0018E644  1A E0 8C 6C 26 B1 99 39 6E 68 9F 20 1D FF DE 5C  鄬l&睓9nh?轡
0018E654  05 79 A5 72 72 32 4C CE BF 90 F5 F8 00 E4 8C E3  yr2L慰愼?鋵?
0018E664  F2 AE 33 FB 03 A4 DA 1C 5C EC D3 3E C7 12 FE B3  虍3?ぺ\煊>?
0018E674  6E A6 2A 9A 5C 00 00 00 00 00 00 00 00 00 00 00  n?歕...........
```

接下来的 五个线程回调函数就是整个程序的重点了

### CreateResFile 第一个线程回调函数 创建00000000.res文件

这个函数在工作路径创建了00000000.res这个文件 并且往里写入数据

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bse8yi61j30z90cwt9h.jpg)

写入的内容如下 其中有0x8个字节的随机数 还有0x4个字节的当前时间  

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bshrmy92j311k0fpaki.jpg)

### CheckDky 第二个线程函数 检测文件是否存在

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsigcqt2j30v90dv0t5.jpg)

这个函数的作用是每个五秒检测工作路径下是否存在774F34B5.dky这个文件 文件名应该是个随机数 不是固定的 如果存在的话会执行sub_10003D10这个函数 由于我的桌面上一直都没有存在 所以这个函数我也就没有去分析

### EncryptAllFiles 第三个线程函数 加密所有文件(重点)

这个函数是整个病毒程序最核心的函数 代码量最多 里里外外总共嵌套了十几层函数  我感觉比整个熊猫烧香的代码还要多  下面是这个函数的第一层

#### 核心加密函数第一层

循环检测是否有新的磁盘加入 如果有 则加密 没有就一直循环  

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsiujr0gj30tb0gu74v.jpg)

#### 核心加密函数第二层

接下来进入到核心函数第二层

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsj77oj4j30vg09w3yw.jpg)

第二层有三个比较重要的函数 每个都有各自的作用 我们重点解析第二个加密函数 

##### MovFileToTemp 移动文件到临时目录下并重命名为.WNCRTY

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsjn1a75j30wr0hnwfn.jpg)

这个函数单独创建了一个线程 将一部分文本文件移动到临时目录下 并进行重命名

 下面是这个函数循环结束后我的临时文件夹下的文件 这些文件并没有加密 是可以直接通过修改后缀名恢复

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsjxur88j30ot0g4775.jpg)

#####  FillDisk  在回收站创建一个文件 并且循环写入数据直到磁盘空间不足

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsk9ksiyj30uc0fjjs0.jpg)

这个函数就比较有意思了  它会在在$RECYCLE下创建一个名为hibsys.WNCRYT的文件  并设置属性为隐藏 然后循环往这个文件写入数据 直到磁盘空间不足跳出循环

当这个函数结束的时候 这个文件居然有39个G

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bskmrg55j30w30hq438.jpg)

##### EncryptFile 加密磁盘上的所有文件

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bskzsmvnj30tb0fvt9j.jpg)

这个函数对磁盘和路径做了一个判断 然后又调用了另外一个函数 我们需要再次进入到这个函数

#### 核心加密函数第三层

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsldtsumj30wx0gfjs2.jpg)

进到第三层之后又有一个函数 这个函数会遍历并且加密所有的文件 而且是递归调用的 然后我们再次进入这个函数

#### 核心加密函数第四层

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bslo1y2rj30ug0ejmxs.jpg)

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsm9vb5oj30uj0ew3z9.jpg)

这个函数首先遍历所有的文件 对文件夹和文件执行不同的操作 并且对后缀名进行过滤 

首先跳过 @Please_Read_Me@.txt，@WanaDecryptor@.exe.lnk， @WanaDecryptor@.bmp

具体类型如下

0 没有后缀以及其他类型后缀

1 .exe, .dll

4 .WNCRYT

5 .WNCYR

6 .WNCRY

2.

```C++
“.doc”".docx”".xls”".xlsx”".ppt”".pptx”".pst”".ost”".msg”".eml”".vsd”".vsdx”

“.txt”".csv”".rtf”".123″”.wks”".wk1″”.pdf”".dwg”".onetoc2″”.snt”".jpeg”".jpg”
```

3.

```C++
“.docb”".docm”".dot”".dotm”".dotx”".xlsm”".xlsb”".xlw”".xlt”".xlm”".xlc”".xltx”".xltm”".pptm”".pot”".pps”".ppsm”".ppsx”".ppam”".potx”".potm”

“.edb”".hwp”".602″”.sxi”".sti”".sldx”".sldm”".sldm”".vdi”".vmdk”".vmx”".gpg”".aes”".ARC”".PAQ”".bz2″”.tbk”".bak”".tar”".tgz”".gz”".7z”".rar”

“.zip”".backup”".iso”".vcd”".bmp”".png”".gif”".raw”".cgm”".tif”".tiff”".nef”".psd”".ai”".svg”".djvu”".m4u”".m3u”".mid”".wma”".flv”".3g2″”.mkv”

“.3gp”".mp4″”.mov”".avi”".asf”".mpeg”".vob”".mpg”".wmv”".fla”".swf”".wav”".mp3″”.sh”".class”".jar”".java”".rb”".asp”".php”".jsp”".brd”".sch”

“.dch”".dip”".pl”".vb”".vbs”".ps1″”.bat”".cmd”".js”".asm”".h”".pas”".cpp”".c”".cs”".suo”".sln”".ldf”".mdf”".ibd”".myi”".myd”".frm”".odb”".dbf”

“.db”".mdb”".accdb”".sql”".sqlitedb”".sqlite3″”.asc”".lay6″”.lay”".mml”".sxm”".otg”".odg”".uop”".std”".sxd”".otp”".odp”".wb2″”.slk”".dif”".stc”

“.sxc”".ots”".ods”".3dm”".max”".3ds”".uot”".stw”".sxw”".ott”".odt”".pem”".p12″”.csr”".crt”".key”".pfx”".der”
```

总结为下面的枚举

```C++
enum FILE_TYPE
{
    FILE_TYPE_NULL = 0,

    FILE_TYPE_EXEDLL,

    FILE_TYPE_DOC,

    FILE_TYPE_DOCEX,

    FILE_TYPE_WNCRYT, //.wncryt

    FILE_TYPE_WNCYR, //.wncyr

    FILE_TYPE_WNCRY //.wncry
}
```



#### 核心加密函数第五层

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsmpvnr1j30s80ga74t.jpg)

这个函数首先会调用sub_10002E70这个函数 根据这个函数返回值的不同 执行不同的加密策略 对加密策略做一个总结

1. 在枚举文件中，cmd=1，会对普通文件直接加密为.WNCRY，不再加入链表，大文件处理为.WNCYR，以及其他未作处理文件继续加入链表等待处理
2. 枚举完成后，cmd从2-4，每个cmd遍历都遍历加密文件 cmd=2，加密FILE_TYPE_DOCEX普通文件为.WNCRY（移出链表），以及FILE_TYPE_DOCEX大文件为.WNCYR  cmd=2, 删除.WNCRYT 
3. cmd=3, 加密链表中所有文件（移出链表）
4.  cmd=4, 加密可能剩余链表中的文件

 虽然操作不同 但是加密函数是同一个 接下来再次进入EncryptFiles

#### 核心加密函数第六层

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsn39v2qj30wc0h1aas.jpg)

这个加密函数首先做了一些准备工作 获取文件的后缀名 然后跟.WNCRY做判断 如果比较成功 则不加密 接着做了一个字符串拼接 然后才开始加密文件 那么我们还要再往里跟一层

#### 核心加密函数第七层

接下来是这个程序的核心的加密算法了 他加密的步骤如下

1. 读取文件前0x8个字节的内容 跟WANACRY!作比较 

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsnfmcfyj30we0gu0ti.jpg)

2. 使用原文件名+.WNCRYT 创建一个新文件 创建的时候这个文件并没有任何内容

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsnqdkoij30sz09i3yn.jpg)

3. 对创建的文件写入数据 

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bso1kjpmj30qs0alglw.jpg)

4. 读取原文件 将加密后的文件内容写入到创建的文件

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsogcywvj30w70ch0t3.jpg)

至此 病毒的加密函数就分析完成

### StartTaskdl 第四个线程回调函数 以隐藏的方式启动taskdl.exe

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsoy7fazj30wr0gxgmf.jpg)

这个函数每隔三秒以隐藏的方式启动taskdl.exe 那么接下来还需要对taskdl.exe进行分析

### StartExeAndSetReg 第五个线程回调函数 启动taskse.exe和@WanaDecryptor@.exe并且修改注册表

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bspl5br9j30tm0eqgm4.jpg)

这个函数每隔三秒会启动工作路径的taskse.exe和@WanaDecryptor@.exe并且使用cmd设置注册表启动项

#### 启动taskse.exe

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsq1pydqj30z90gs3zb.jpg)

这个函数以命令行的方式启动taskse.exe  参数为为C:\Users\GuiShou\Desktop\@WanaDecryptor@.exe 这个参数需要暂时记住 待会分析taskse.exe的时候需要用到

并且以命令行的方式显式启动@WanaDecryptor@.exe 这个是病毒的解密器

#### 设置注册表启动项

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsqvzw8xj30x30f0dgi.jpg)

函数将获取到的随机的字母+数字设置到注册表启动项  但是在我的机器上是设置失败的 因为命令敲错了 正确的命令应该是这个

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsrc7la7j30wr0fj42j.jpg)

### RepeatOperation 一些重复操作

这个是整个病毒程序最后一个函数了 

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsro368cj30r10eat9a.jpg)

这个函数有三个函数比较重要

#### 1. RunBat 创建并启动批处理脚本

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsrz90e9j30v60ey74u.jpg)

这个函数会检测@WanaDecryptor@.exe.lnk是否存在  如果不存在 就创建一个批处理脚本 并且将命令写入到.bat脚本 这个脚本的作用仅仅的给@WanaDecryptor@.exe创建一个快捷方式

#### 2.CreateReadMe 创建@Please_Read_Me@.txt

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bssbl0cjj30sp0eidg6.jpg)

这个函数首先检测工作路径下的@Please_Read_Me@.txt是否存在 如果不存在 就从r.wrny中读取内容 并写入到@Please_Read_Me@.txt 这个是病毒的勒索文档

#### 3.EncryptOtherUsersFiles 加密其他所有用户的文件

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bssu87x6j30sr0b8dga.jpg)

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bst6n67zj30v50bmdg7.jpg)

这个函数的作用是获取windows所有的用户名 并检测是否和当前的用户名一致 如果不一致 就加密那个用户的所有文件 用的还是刚刚我们分析过的加密函数

剩下的就都是一些重复操作了  至此病毒的核心程序就分析完成

## 对taskdl.exe的分析 

接下来我们来对病毒程序释放的taskdl.exe做一个详细的分析 taskdl.exe的主函数如下

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bston1kqj30sn0cbmxj.jpg)

那么从上面可以看到这个exe的代码量比起其他两个来说可以说是简单的多的多的多了 其中最核心的函数只有一个 就是上面的**DeleteFile**这个函数  接下来进入到这个函数进行详细分析

### DeleteFile 删除回收站和临时目录下的.WNCRY文件

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsu49o4lj30ug0dwaal.jpg)

###  GetRecyclePathOrTempPath

首先是` GetRecyclePathOrTempPath`这个函数 这个函数在病毒的主程序里面也有 它会返回两个路径 一个是回收站路径 也就是`D:\$RECYCLE ` 第二个是系统盘的临时文件夹的路径 `C:\Users\GuiShou\AppData\Local\Temp`

接着这个函数会循环两次 然后对这两个文件夹做处理 由于我的虚拟机环境只有一个C盘和D盘 所以我并不知道如果多一个盘会出现什么情况

### 遍历文件

接着函数会调用FindFirstFileW这个函数查找目标文件夹中所有.WNCRYT 结尾的文件  第一次循环我这里失败直接返回  因为我的回收站并没有.WNCRYT 结尾的文件 但是我们要分析另外一条分支 所以我在临时文件夹下创建了这么几个文件来方便调试

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsugqgb9j30xk0atq4x.jpg)

如果FindFirstFileW调用成功 就会走下面的分支

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsutxchdj30sj0chdg4.jpg)

首先这个它会遍历所有的.WNCRY文件 并且将文件的完整路径和长度存储到一个容器中 如下图

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsvul0iaj30qp0g6n05.jpg)

### 删除文件

当文件遍历结束 会调用DeleteFileW删除所有的.WNCRY后缀的文件

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsw7suf1j30tu09cwel.jpg)

### 收尾 释放内存

 接着 这个函数的功能就算是完成了 

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bswiia6bj30ug0dgq3a.jpg)

函数末尾循环将存放文件的完整路径和长度的容器清空 然后释放内存

至此 taskdl.exe这个文件就分析完成 主要的作用就是删除回收站和临时目录下的.WNCRY文件

## 对taskse.exe的分析 

接下来对病毒释放的taskse做一个分析 主体逻辑如下

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bswsvmjwj30q306p0st.jpg)

在主函数对命令行参数做了一个判断 如果小于2直接退出 由于我们已经在主程序中得知了这个程序启动的附加参数 所以直接载入OD 填入附加参数调试进程 接下来进入到主函数

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsxcuqfvj30vf0d7dge.jpg)

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsxm0unzj30r60cudg1.jpg)

这个函数首先获取了一些必要的API函数地址

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsxwxdjwj30u50ccmxi.jpg)

然后提升当前权限

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0btm56yzgj30ty0bs3yn.jpg)

接着获取用户的访问令牌 并创建一个新的访问令牌

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsye8mk6j30u60dst92.jpg)

接着再次提升权限

函数结束 所以得出结论 这个taskse.exe是提权相关的程序

## 对wcry释放文件的总结

整个分析完成 接下来对病毒释放的文件做一个总结

- msg 病毒的语言包
- c.wnry 存储了比特币账户 一个下载链接 跟勒索相关 
- t.wnry 隐藏了一个dll文件 dll的导出函数是病毒的核心代码 
- u.wnry 解密器
- r.wrny 勒索文档
- @WanaDecryptor@.exe 解密器
- taskse.exe 提权部分
- taskdl.exe删除临时文件和回收站的.WNCRY文件
- 00000000.pky 公钥
- 00000000.eky 被加密的私钥 
- 00000000.res 八个字节的随机数和当前时间
- .bat为解密器创建快捷方式

## 对wannacry总体行为的总结

![](https://ws1.sinaimg.cn/large/006Rs2Luly1g0bsyt0hhlj31aa11jac6.jpg)

# 解决方案

1. 打补丁  由于此次勒索病毒大范围传播是由于很多机器没有打补丁，被攻击之后导致中毒 没有中毒的机器，尽快打补丁可以避免中毒
2. 关闭端口 由于此漏洞需要利用445端口传播，关闭端口 漏洞就无法利用
3. 创建互斥体  由于加密器，启动之后会检测是否已经有加密器程序存在，防止互相之间干扰，所以会创建互斥体MsWinZonesCacheCounterMutexA。只要检测到互斥体存在就会关闭程序。安全软件可以利用这一点 让病毒运行之后自动退出，无法加密文件

相关文件下载Github：https://github.com/TonyChen56/WannaCry-
