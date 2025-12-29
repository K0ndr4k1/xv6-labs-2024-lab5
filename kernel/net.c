#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "net.h"

// xv6's ethernet and IP addresses
static uint8 local_mac[ETHADDR_LEN] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
static uint32 local_ip = MAKE_IP_ADDR(10, 0, 2, 15);

// qemu host's ethernet address.
static uint8 host_mac[ETHADDR_LEN] = { 0x52, 0x55, 0x0a, 0x00, 0x02, 0x02 };

static struct spinlock netlock;

void
netinit(void)
{
  initlock(&netlock, "netlock");
}


//
// bind(int port)
// prepare to receive UDP packets address to the port,
// i.e. allocate any queues &c needed.
//
uint64
sys_bind(void)
{
  //
  // Your code here.
  //
int port;
  struct proc *p = myproc();

  // 1. 获取系统调用参数 (int port)
  if(argint(0, &port) < 0)
    return -1;

  // 2. 查找一个空闲的 socket 位置，并绑定端口
  // 注意：这里需要简单的锁机制来防止竞态
  for(int i = 0; i < NSOCK; i++) {
    acquire(&sockets[i].lock);
    if(sockets[i].valid == 0) {
      sockets[i].port = port;
      sockets[i].valid = 1;
      sockets[i].rxq = 0; // 队列清空
      release(&sockets[i].lock);
      return 0;
    }
    release(&sockets[i].lock);
  }

  return -1; // 没有空闲 socket
  
}

//
// unbind(int port)
// release any resources previously created by bind(port);
// from now on UDP packets addressed to port should be dropped.
//
uint64
sys_unbind(void)
{
  //
  // Optional: Your code here.
  //

  return 0;
}

//
// recv(int dport, int *src, short *sport, char *buf, int maxlen)
// if there's a received UDP packet already queued that was
// addressed to dport, then return it.
// otherwise wait for such a packet.
//
// sets *src to the IP source address.
// sets *sport to the UDP source port.
// copies up to maxlen bytes of UDP payload to buf.
// returns the number of bytes copied,
// and -1 if there was an error.
//
// dport, *src, and *sport are host byte order.
// bind(dport) must previously have been called.
//
uint64
sys_recv(void)
{
  //
  // Your code here.
  //
  //int dport; // 目标端口
  uint64 src_ip_addr; // 用户态指针：存源IP
  uint64 src_port_addr; // 用户态指针：存源端口
  uint64 buf_addr; // 用户态指针：存数据
  int maxlen;

  // 获取参数
  if(argint(0, &dport) < 0 || argaddr(1, &src_ip_addr) < 0 ||
     argaddr(2, &src_port_addr) < 0 || argaddr(3, &buf_addr) < 0 ||
     argint(4, &maxlen) < 0)
    return -1;

  // 寻找对应的 socket
  int i;
  int index = -1;
  for(i = 0; i < NSOCK; i++){
    acquire(&sockets[i].lock);
    if(sockets[i].valid && sockets[i].port == dport){
      index = i;
      // 保持持有锁，进入循环
      break;
    }
    release(&sockets[i].lock);
  }

  if(index == -1) return -1; // 端口未绑定

  struct sock *s = &sockets[index];

  // 循环等待数据
  while(s->rxq == 0){
    // 如果没有数据，进入睡眠，释放锁
    sleep(s, &s->lock);
    // 醒来后重新持有锁，再次检查
    if(myproc()->killed){
      release(&s->lock);
      return -1;
    }
  }

  // 取出队列头的包
  struct mbuf *m = s->rxq;
  s->rxq = m->next;
  release(&s->lock); // 数据取出来了，可以放锁了

  // 提取包里的信息 (注意：m->head 现在指向 Payload)
  // 但是我们需要 IP 和 UDP 头里的源地址信息
  // 这里的难点是：我们在 ip_rx 里已经 mbufpull 过了，头信息“丢”了吗？
  // 答：mbufpull 只是移动 head 指针。IP/UDP 头还在 m->head 的前面内存里。
  // 我们需要倒推回去找 header。

  // 恢复 UDP 头指针
  struct udp *udph = (struct udp *)(m->head - sizeof(struct udp));
  // 恢复 IP 头指针
  struct ip *iph = (struct ip *)(m->head - sizeof(struct udp) - sizeof(struct ip));

  uint32 src_ip = ntohl(iph->ip_src);
  uint16 src_port = ntohs(udph->sport);
  int len = m->len;
  if(len > maxlen) len = maxlen;

  // 拷贝数据到用户空间
  if(copyout(myproc()->pagetable, src_ip_addr, (char*)&src_ip, sizeof(src_ip)) < 0 ||
     copyout(myproc()->pagetable, src_port_addr, (char*)&src_port, sizeof(src_port)) < 0 ||
     copyout(myproc()->pagetable, buf_addr, m->head, len) < 0){
       mbuffree(m);
       return -1;
  }

  mbuffree(m); // 释放内核 buffer
  return len; // 返回读取的字节数
  
}

// This code is lifted from FreeBSD's ping.c, and is copyright by the Regents
// of the University of California.
static unsigned short
in_cksum(const unsigned char *addr, int len)
{
  int nleft = len;
  const unsigned short *w = (const unsigned short *)addr;
  unsigned int sum = 0;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(const unsigned char *)w;
    sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  /* guaranteed now that the lower 16 bits of sum are correct */

  answer = ~sum; /* truncate to 16 bits */
  return answer;
}

//
// send(int sport, int dst, int dport, char *buf, int len)
//
uint64
sys_send(void)
{
  struct proc *p = myproc();
  int sport;
  int dst;
  int dport;
  uint64 bufaddr;
  int len;

  argint(0, &sport);
  argint(1, &dst);
  argint(2, &dport);
  argaddr(3, &bufaddr);
  argint(4, &len);

  int total = len + sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp);
  if(total > PGSIZE)
    return -1;

  char *buf = kalloc();
  if(buf == 0){
    printf("sys_send: kalloc failed\n");
    return -1;
  }
  memset(buf, 0, PGSIZE);

  struct eth *eth = (struct eth *) buf;
  memmove(eth->dhost, host_mac, ETHADDR_LEN);
  memmove(eth->shost, local_mac, ETHADDR_LEN);
  eth->type = htons(ETHTYPE_IP);

  struct ip *ip = (struct ip *)(eth + 1);
  ip->ip_vhl = 0x45; // version 4, header length 4*5
  ip->ip_tos = 0;
  ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udp) + len);
  ip->ip_id = 0;
  ip->ip_off = 0;
  ip->ip_ttl = 100;
  ip->ip_p = IPPROTO_UDP;
  ip->ip_src = htonl(local_ip);
  ip->ip_dst = htonl(dst);
  ip->ip_sum = in_cksum((unsigned char *)ip, sizeof(*ip));

  struct udp *udp = (struct udp *)(ip + 1);
  udp->sport = htons(sport);
  udp->dport = htons(dport);
  udp->ulen = htons(len + sizeof(struct udp));

  char *payload = (char *)(udp + 1);
  if(copyin(p->pagetable, payload, bufaddr, len) < 0){
    kfree(buf);
    printf("send: copyin failed\n");
    return -1;
  }

  e1000_transmit(buf, total);

  return 0;
}

void
ip_rx(char *buf, int len)
{
  // don't delete this printf; make grade depends on it.
  static int seen_ip = 0;
  if(seen_ip == 0)
    printf("ip_rx: received an IP packet\n");
  seen_ip = 1;

  //
  // Your code here.
  //
 if(len < sizeof(struct eth) + sizeof(struct ip)) {
    kfree(buf);
    return;
  }

  struct ip *ip = (struct ip*)(buf + sizeof(struct eth));

  // Verify IP Checksum
  if(in_cksum((unsigned char*)ip, sizeof(struct ip)) != 0) {
    kfree(buf);
    return;
  }

  // Check if it is UDP
  if(ip->ip_p != IPPROTO_UDP) {
    kfree(buf);
    return;
  }

  // Check buffer length validity for UDP header
  if(len < sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp)) {
    kfree(buf);
    return;
  }

  struct udp *udp = (struct udp*)(ip + 1);
  uint16 dport = ntohs(udp->dport);

  // Find destination socket
  struct sock *s = 0;
  acquire(&netlock);
  for(int i = 0; i < NSOCK; i++) {
    if(sockets[i].port == dport) {
      s = &sockets[i];
      acquire(&s->lock);
      break;
    }
  }
  release(&netlock);

  // If socket found, enqueue the packet
  if(s) {
    struct rx_entry *e = (struct rx_entry*)kalloc();
    if(e == 0) {
      release(&s->lock);
      kfree(buf);
      return;
    }
    
    e->buf = buf;
    e->len = len;
    e->next = 0;

    if(s->rx_tail) {
      s->rx_tail->next = e;
    } else {
      s->rx_head = e;
    }
    s->rx_tail = e;
    
    wakeup(s); // Wake up sys_recv
    release(&s->lock);
  } else {
    // No socket bound to this port, drop packet
    kfree(buf);
  } 
}

//
// send an ARP reply packet to tell qemu to map
// xv6's ip address to its ethernet address.
// this is the bare minimum needed to persuade
// qemu to send IP packets to xv6; the real ARP
// protocol is more complex.
//
void
arp_rx(char *inbuf)
{
  static int seen_arp = 0;

  if(seen_arp){
    kfree(inbuf);
    return;
  }
  printf("arp_rx: received an ARP packet\n");
  seen_arp = 1;

  struct eth *ineth = (struct eth *) inbuf;
  struct arp *inarp = (struct arp *) (ineth + 1);

  char *buf = kalloc();
  if(buf == 0)
    panic("send_arp_reply");
  
  struct eth *eth = (struct eth *) buf;
  memmove(eth->dhost, ineth->shost, ETHADDR_LEN); // ethernet destination = query source
  memmove(eth->shost, local_mac, ETHADDR_LEN); // ethernet source = xv6's ethernet address
  eth->type = htons(ETHTYPE_ARP);

  struct arp *arp = (struct arp *)(eth + 1);
  arp->hrd = htons(ARP_HRD_ETHER);
  arp->pro = htons(ETHTYPE_IP);
  arp->hln = ETHADDR_LEN;
  arp->pln = sizeof(uint32);
  arp->op = htons(ARP_OP_REPLY);

  memmove(arp->sha, local_mac, ETHADDR_LEN);
  arp->sip = htonl(local_ip);
  memmove(arp->tha, ineth->shost, ETHADDR_LEN);
  arp->tip = inarp->sip;

  e1000_transmit(buf, sizeof(*eth) + sizeof(*arp));

  kfree(inbuf);
}

void
net_rx(char *buf, int len)
{
  struct eth *eth = (struct eth *) buf;

  if(len >= sizeof(struct eth) + sizeof(struct arp) &&
     ntohs(eth->type) == ETHTYPE_ARP){
    arp_rx(buf);
  } else if(len >= sizeof(struct eth) + sizeof(struct ip) &&
     ntohs(eth->type) == ETHTYPE_IP){
    ip_rx(buf, len);
  } else {
    kfree(buf);
  }
}
