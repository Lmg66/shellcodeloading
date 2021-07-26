### shellcodeloading

golang版 shellcode 加载器 

效果:实测可免杀360 火绒

### 原理

[小玉玉yyds](https://www.bilibili.com/video/BV1jr4y1c7gJ)

### 目录说明

```
│  1.jpg        
│  go.mod
│  README.md
│  shellcodeloading.go              //生成output/shellcode.go imageshellcode
│
├─.idea
│      .gitignore
│      modules.xml
│      shellcodeloading.iml
│      workspace.xml
│
├─aes                               //aes加密调用包
│      aseCode.go
│ 
├─checkSandbox						//沙箱检测调用包 20个进程 系统盘大于45g
│      checkSandbox.go
│
└─output
        compileShellGo.bat //用于编译shellcode.go—>shellcode.exe 由shellcodeloading.go调用
        lnng.jpg         		 //含有shellcode aes密钥
        shellcode.exe			
        shellcode.go			//用于生成shellcode.exe
```

### 使用

#### 环境

需要golang环境

因为shellcode.go 木马需要编译

#### 使用步骤

1.生成shellcode

![](https://cdn.jsdelivr.net/gh/Lmg66/picture@main/image/1627206352705-image-20210725174518720.png)

![](https://cdn.jsdelivr.net/gh/Lmg66/picture@main/image/1627206482200-image-20210725174746525.png)

![](https://cdn.jsdelivr.net/gh/Lmg66/picture@main/image/1627206691165-image-20210725175115790.png)

![](https://cdn.jsdelivr.net/gh/Lmg66/picture@main/image/1627206783230-image-20210725175253002.png)

2.生成shellcode.exe

shellcodeloading目录

![](https://cdn.jsdelivr.net/gh/Lmg66/picture@main/image/1627206894340-image-20210725175442184.png)

选择想要的shellcode.exe方式

这里演示其中一种(分离免杀，imageshellcode路径写死在shellcode.exe中，远程加载shellcode)

![](https://cdn.jsdelivr.net/gh/Lmg66/picture@main/image/1627207169249-image-20210725175903529.png)

在output目录下我们就可以看到我们生成的shellcode.go(木马原文件) shellcode.exe(木马文件) lnng.jpg(分离免杀的shellcode)

将shellcode.exe 拖入带杀软的虚拟机中

这里用python3开启简单http服务，来加载imageshellcode，可以上传到图床等等地方(注意图片别被压缩)，地址别搞错就行

![](https://cdn.jsdelivr.net/gh/Lmg66/picture@main/image/1627207554631-image-20210725180505277.png)

#### 免杀效果

[https://www.bilibili.com/video/BV1Hq4y1p7c1](https://www.bilibili.com/video/BV1Hq4y1p7c1)

![](https://cdn.jsdelivr.net/gh/Lmg66/picture@main/image/1627214620018-image-20210725200323206.png)

### 参考文章说明

[**yuppt**大佬视频](https://space.bilibili.com/50908119?spm_id_from=333.788.b_765f7570696e666f.2)

[https://gitee.com/cutecuteyu/picshell_bypassav](https://gitee.com/cutecuteyu/picshell_bypassav)

初学内网渗透，大佬们轻点喷

仅限技术分享研究与讨论，严禁用于非法用途，产生的一切后果自行承担

