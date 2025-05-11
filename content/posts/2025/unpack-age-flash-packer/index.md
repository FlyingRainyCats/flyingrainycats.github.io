+++
date = '2025-05-11T09:39:02+09:00'
title = '解包 AGE Flash Packer 生成的可执行文件'
description = '透过逆向分析 AGE Flash Packer 生成的可执行文件，最终编写一个资源提取工具。'
summary = '逆向分析 AGE Flash Packer 生成的文件并提取资源。'
+++

## 前因

起因是在论坛收到一则求助：

> 求助关于雅致Flash播放器(AGE FlashPacker)的数据解密问题  
> (出处: [吾爱破解论坛](https://www.52pojie.cn/thread-2030470-1-1.html))

文中给出了一个样本文件：

- [蓝奏网盘](https://wwio.lanzoub.com/iPVRq2vvpedc)
- [百度网盘](https://pan.baidu.com/s/1kI9o5n8ARTx2--OXTreJnw?pwd=52pj)（备份）

下面是对应的 SHA256 校验值：

```text
9d139494eba8891846a0ce961c1f3235c4eefb1d9d04018da2a585e681af7744 *ebook.exe
```

## 文件末尾

在文件的末尾可以看到类似这样的内容：

```yaml
文件偏移: 0x014fd711

字符串:
  长度: 0D 00 # =0x0d, 13
  内容: "untitled1.swf"

未知内容: # 未知 1
  20 03 00 00 58 02 00 00 00 00 00 00 00 01

签名信息:
  "AGE Flash Player"

未知内容:
  未知2: 11 D7 4F 01 # =0x014fd711
  未知3: 00 20 0C 00
  未知4: 80 95 2D 00
  未知5: 3E D3 4F 01 # =0x014fd33e
  未知6: 43 00 00 00 # =0x43
```

其中，未知内容块有一些看起来像是在引用文件结尾的数据。

- 「未知 2」看起来指向这段元信息开始处
- 「未知 5」看起来是某个数据的偏移

其它未知内容信息不足以判定到底在干什么，因此看看「未知 5」的内容：

```text
14F:D33E  78 01 6D 94                                      x.m”
```

这个 `78 01` 看起来就是 zlib 压缩后的数据。虽然不清楚具体数据有多大，保险起见将元数据前的内容全部一起解压看看：

```py
# 安装依赖: pip install hexdump2
from hexdump2 import hexdump
import os
import zlib

with open("ebook.exe", "rb") as f:
    f.seek(0x014FD33E, os.SEEK_SET)
    data = f.read(0x014FD711 - 0x014FD33E) # 不填这个参数读到结尾也可以
data = zlib.decompress(data)
hexdump(data)  # 或直接 print(data) 查看
```

可以看到这样的数据：

```text
00000000  81 2c 25 00 21 16 66 00  00 90 01 00 0d 00 75 6e  |.,%.!.f.......un|
00000010  74 69 74 6c 65 64 31 2e  73 77 66 a2 42 8b 00 66  |titled1.swf.B..f|
00000020  69 17 00 00 90 01 00 0e  00 73 72 63 5c 62 67 6d  |i........src\bgm|
00000030  5c 30 31 2e 6d 70 33 08  ac a2 00 42 60 19 00 00  |\01.mp3....B`...|

                            ... 省略 ...

000007d0  dc 00 00 0d 00 73 72 63  5c 69 6d 67 5c 63 2e 6a  |.....src\img\c.j|
000007e0  70 67                                             |pg|
000007e2
```

看起来像是「打包」的文件清单以及一些基本信息。

## 文件清单

这个格式相对比较简单，大概如下：

```yaml
地址:  81 2c 25 00  # =0x00252c81
未知1: 21 16 66 00  # =0x00661621
未知2: 00 90 01 00  # =0x00019000

字符串:
  长度: 0d 00 (=0x0d, 13)
  内容: "untitled1.swf"
```

后面的内容都是重复该格式，直到数据结尾。

你可能注意到上面有个未知内容，这个稍后会提到。

偏移 `0x00252c81` 处的数据大概是这样：

```text
025:2C81  05 00 00 00 96 DA 9D EE 4D F8 A8 80 B0 B6 6E B9  ....–Ú.îMø¨€°¶n¹ 
```

可以看到没有明显的特征。

## 分析算法？

原帖找到了一个处理内嵌文件的关键函数 `00498B80`，去使用 IDA 分析吧。

有些 Delphi 的内置函数被 IDA 自动签名识别出来了，因此逻辑还是相对比较清晰的。

但是注意：虚表调用/结构体缺少数据，这部分只能手动分析然后补上。

将 `00498B80` 反编译，然后稍作整理：

```cpp
using Webadapt::TDefaultFieldsPagedAdapter::ExtractRequestParams;
using Classes::TList;

bool __fastcall ServeRequest_498B80(
  TRequest *req,
  int uri,
  TWriterStream *res
) {
  bool encrypted = 0;
  if ( uri ) {
    int param = ExtractRequestParams(req, uri);
    if ( param >= 0 ) {
      TFileEntry * file = (TFileEntry *)TList::Get(req->files, param);
      req->reader->vtb->Seek(req->reader, file->offset, SEEK_SET);
      if ( (int)file->enc_size <= 0 )
        Send_498954(req, res, file->size, 0);
      else
        DecryptSend_4989A0(req, &res, file->size, file->enc_size);
      encrypted = 1;
    }
  }
  return encrypted;
}
```

结合动态调试，可以发现执行 `call ebook.4989A0` 后会产生解密后的数据：

```x86asm
loc_00498BDE:
  push eax
  lea edx,dword ptr ss:[ebp-8] ; 输出
  mov ecx,dword ptr ds:[esi+4] ; 输入
  mov eax,ebx
  call ebook.4989A0
  jmp ebook.498BFD             ; [[ebp-0x08]+4] => 解密后的数据
```

因此继续深入 `4989A0` 的解密逻辑：

```c
int __fastcall DecryptSend_4989A0(
  TRequest *req,
  TWriterStream **res,
  int full_len,
  int enc_len
) {
  TFileHeader hdr; // size=12
  BufferRead_41B1D8(req->reader, &hdr, sizeof(hdr));

  TCipher *cipher = (TCipher *)CipherFactory_493274(hdr.magic);
  CipherInit_492520(cipher, &"AGE_Flash_Player");

  if ( IsClass(cipher, &cls_DCPcrypt_TDCP_blockcipher) ){
    cipher->mode = ENC_MODE_CFB;
  }

  // 测试解密，不相等就报错。
  cipher->vtb->decrypt(cipher, &hdr.cipher, &hdr.cipher, 12);
  if ( hdr.cipher != hdr.plain ) {
    RaiseExcept(ExceptionFactory(error_ctx)); // 抛出错误
  }

  // 解密文件头
  DecryptStream_4925C0(cipher, req->reader, *res, enc_len);

  // 如果还有数据，将剩下的数据拷贝过去
  if ( enc_len < full_len - 12 ) {
    Send_498954(req, *res, full_len - 12 - enc_len, NULL);
  }

  // 清理并释放资源
  cipher->vtb->Burn(cipher);
  System::TObject::Free(cipher);

  return NULL;
}
```

这里静态分析会比较困难，带着调试器跟一下数据会好很多。

比如静态看不出什么东西的这两个函数：

- `CipherFactory_493274` 可以发现是从已注册的实例列表挑选对应的算法：
  - `0x02` 是 SHA1
  - `0x05` 是 Blowfish
- `CipherInit_492520` 可以发现参数传入了透过 `cls_Sha1_TDCP_sha1` 构建的对象。
  - 合理猜测就是 `SHA1("AGE_Flash_Player")`，跟踪发现确实如此。

看起来并没有什么魔改的地方，剩下的就很简单了… 对吧？

## DPCrypt

> DPCrypt 这么成熟的库，与其它语言的实现一定能兼容的对吧？对吧？？

可执行文件内置了一些符号，例如可以看出程序中的 `SHA1` 和 `Blowfish` 实现来自 `DPCrypt`。

虽然对算法本身的实现（即：ECB 模式下）是「标准」的，但当数据长度未与块大小对齐的情况下，实现比较奇怪：

```pas {linenos=inline, hl_lines=["22-27"]}
procedure TDCP_blockcipher64.DecryptCFBblock(const Indata; var Outdata; Size: longword);
var
  i: longword;
  p1, p2: PByte;
  Temp: array[0..7] of byte;
begin
  if not fInitialized then
    raise EDCP_blockcipher.Create('Cipher not initialized');
  p1:= @Indata;
  p2:= @Outdata;
  FillChar(Temp, SizeOf(Temp), 0);
  for i:= 1 to (Size div 8) do
  begin
    Move(p1^,Temp,8);
    EncryptECB(CV,CV);
    Move(p1^,p2^,8);
    XorBlock(p2^,CV,8);
    Move(Temp,CV,8);
    p1:= PByte(PByte(p1) + 8);
    p2:= PByte(PByte(p2) + 8);
  end;
  if (Size mod 8)<> 0 then
  begin
    EncryptECB(CV,CV);
    Move(p1^,p2^,Size mod 8);
    XorBlock(p2^,CV,Size mod 8);
  end;
end;
```

（来源：[SnakeDoctor/DCPcrypt: `DCPblockciphers.pas`][dcp_cfb]；正确做法是使用 `pkcs1` 之类的填充方案）

[dcp_cfb]: https://github.com/SnakeDoctor/DCPcrypt/blob/f319817/DCPblockciphers.pas#L319

因此如果需要使用其它语言实现，那么需要利用 `ECB` 模式，来手动实现 `DPCrypt` 版的 `CFB` 模式。

※ 它的 IV 生成看起来也是非标行为，有兴趣的同学可以自行尝试逆向。

这部分的实现参考之后给出的实现吧。

## 解密流程

> 需要的信息都有了，总结一下流程。

首先是「读取可执行文件信息」，也就是文件末尾的 20 个字节：

```yaml
末尾数据:
  元数据偏移: u32 # 例 0x014fd711
  未知3:      u32
  未知4:      u32
  清单偏移:   u32 # 例 0x014fd33e
  未知6:      u32
```

然后就是文件清单。

- 读取「清单偏移」与「元数据偏移」之间的数据
- 使用 `zlib.decompress` 解压缩

文件清单的格式如下：

```yaml
数据偏移: u32
完整长度: u32
加密长度: u32

文件名:
  长度: u16
  内容: Vec<u8> # 文件名长度为 "$.文件名.长度"
```

剩下的就是依次进行提取了：

- 跳到指定数据偏移处
- 读入加密数据长度的内容
  - 初始化 Blowfish 算法，并进行解密
- 读入「完整长度 - 加密长度 - 12」字节的数据
  - 这部分数据不需要解密，直接写出即可

到此，提取流程就完成了。

## 参考实现

使用 Python 做了个简单的实现，大概只支持某一个版本的 AGE 打包器生成的文件。

⇒ [github.com/FlyingRainyCats/age_unpack](https://github.com/FlyingRainyCats/age_unpack)

※ 上述解包项目使用 [MIT 授权协议](https://github.com/FlyingRainyCats/age_unpack/blob/main/LICENSE)。
