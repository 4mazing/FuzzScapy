# FuzzScapy
FuzzScapy python script?  

## Usage  

>     python fuzz_socket.py srcIP dstIP dport

## version 0.3

* 要死了,思路越想越混乱,肯定不是我想的复杂了  
* 虚拟机的iptables被我添加了规则丢掉了所有的RST包  
* 暂时选择了一个折中的办法,每次发送的数据并不是每一条都会被RST掉,所以把发送成功并且在设备没有返回RST的时候记录下来,而后发送RST掉这个连接,避免在0.2版本中出现的问题.  
* 可以考虑python多进程的问题,这样是不是会让程序中sniffer的更加准确,我觉得可能会达到这个效果.