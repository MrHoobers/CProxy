ChameleonProxy     http://cproxy.saomeng.club/
======  
  
C语言写的一个TCP、DNS、UDP代理客户端  
以HTTP请求报文的形式发送到目标服务器  
可以修改HTTP请求头，可以兼容部分不规范HTTP请求头  
配合SpecialProxy的编码功能可以实现翻墙  

### 编译:  
~~~~~
Linux/Android:  
    make
Android-ndk:  
    ndk-build  
~~~~~

启动：  
./CProxy CProxy.conf  
关闭：  
./CProxy stop  
查询运行状态：  
./CProxy status  


### 适配服务器程序:  
SpecialProxy(http代理):  
    https://github.com/mmmdbybyd/SpecialProxy  
udpServer(httpUDP代理):  
    https://github.com/mmmdbybyd/CProxy/udpServer/udpServer.c  
    ~~~~~
    #udpServer(httpUDP) -l 监听端口 -e 加密编码
    udpServer -l 8000 -e 170
    ~~~~~