# 免责声明
本工具仅用于技术讨论与学习，利用此工具造成的任何直接或者间接的后果及损失，均由使用者本人负责，本工具作者不为此承担任何责任。
# eBPFPortMuxter
一款通过eBPF实现HTTP端口复用的后门，可以实现无端口，木马流量与正常流量一起流动，增大检测难度。
基本思路：  
1. 通过eBPF获取网卡上所有的进出流量，然后在内核态解析流量包是否为HTTP包，如果为HTTP包则发送到用户态；  
2. 用户态接收到HTTP包后解析出Get参数，参考一句话木马的思想，我们预设两个特殊的参数，一个携带要执行的命令，一个携带接收回显的地址；
3. 用户态匹配特殊参数，匹配成功则执行命令并发送回显。

# 环境要求
1. 内核版本至少为4.15.0；
2. Root权限；
3. Python3，且requests>=2.31.0、bcc>=0.12.0。

# 其他
该后门是对BCC官方例子http-parse-simple的修改，增加了参数解析匹配和命令执行、发送回显的逻辑。为防止此项目被不法分子滥用，代码已做无害化处理，仅证明有效。