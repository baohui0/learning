# 使用KubeAdmin搭建一个K8S集群

## 1.机器及环境准备

### 1.1 硬件要求

每台机器需要2CPU及2G以上的RAM，否则集群性能将受到影响

### 1.2 环境要求

#### 1.2.1 网络环境

- 需要保证集群中所有机器能够互相连接(所有机器能通过内网或公网互相访问)

1. 如果机器版本较新，并且使用nftables作为iptables系统替代,则需要更改回iptables系统才能正常运行，否则`kubeadmin`不兼容,会破坏`kube-proxy`网络

#### 1.2.2 机器环境

1. 禁用交换分区,保证kubectl能够正常工作.

   在swap启用后，在使用磁盘空间和内存交换数据时，性能表现会较差，会减慢程序执行的速度.

   例如:kubelet 在 1.8 版本以后强制要求 swap 必须关闭.

   [关于关闭swap的具体解释](https://www.cnblogs.com/architectforest/p/12982886.html)

   - 查看swap当前状态

   ```shell
   free -m             
                 			总计         已用        空闲      共享    缓冲/缓存    可用
   内存：       15907        6639         213        1549        9054        7461
   交换：        2047         103          1944
   ```

   - 临时禁用/启用交换分区功能命令:

   ```shell
   swapoff -a	#临时禁用交换分区
   swapon -a	#临时启用关闭的交换分区
   ```

   - 永久关闭swap	(需要重启机器)

   ```shell
   cat /etc/fstab 
   # /etc/fstab: static file system information.
   #
   # Use 'blkid' to print the universally unique identifier for a
   # device; this may be used with UUID= as a more robust way to name devices
   # that works even if disks are added and removed. See fstab(5).
   #
   # <file system> <mount point>   <type>  <options>       <dump>  <pass>
   # / was on /dev/nvme0n1p2 during installation
   UUID=15d4ac36-3178-4b2a-82d1-04b2608743db /               ext4    errors=remount-ro 0       1
   # /boot/efi was on /dev/nvme0n1p1 during installation
   UUID=6243-C860  /boot/efi       vfat    umask=0077      0       1
   /swapfile                                 none            swap    sw              0       0				#将带有swap的那一行注释再重启机器即可永久关闭swap
   ```

   

2. *关闭SELinux(CentOS),否则`kubectl`也不能正常工作

   SELinux:Security-Enhanced Linux，是一个安全子系统

   是一个内核模块，可以最大限度地减小系统中服务进程可访问的资源(最小权限原则)

   为了允许容器访问宿主机的文件系统，需要关闭SELinux.

   [关于关闭SELinux的具体解释](https://www.cnblogs.com/architectforest/p/12987499.html)

   - 查看状态

     ```shell
     sestatus -v
     
     SELinux status:                 enabled
     SELinuxfs mount:                /sys/fs/selinux
     SELinux root directory:         /etc/selinux
     Loaded policy name:             targeted
     Current mode:                   enforcing #当前状态执行中
     Mode from config file:          enforcing
     Policy MLS status:              enabled
     Policy deny_unknown status:     allowed
     Memory protection checking:     actual (secure)
     Max kernel policy version:      31
     ```

   - 临时关闭

     ```shell
     setenforce 0	#设置为Permissive模式(禁用)
     setenforce 1	#设置为Enforcing模式(启用)
     ```

   - 永久关闭

     ```shell
     cat /etc/selinux/config 
     
     # This file controls the state of SELinux on the system.
     # SELINUX= can take one of these three values:
     #     enforcing - SELinux security policy is enforced.
     #     permissive - SELinux prints warnings instead of enforcing.
     #     disabled - No SELinux policy is loaded.
     SELINUX=permissive #改为SELINUX=disabled即可永久关闭
     # SELINUXTYPE= can take one of three values:
     #     targeted - Targeted processes are protected,
     #     minimum - Modification of targeted policy. Only selected processes are protected. 
     #     mls - Multi Level Security protection.
     SELINUXTYPE=targeted
     ```

#### 1.2.3 端口环境

- Master节点需要开放端口:

| 协议 | 方向 | 端口范围  | 作用                    | 使用者                       |
| ---- | ---- | --------- | ----------------------- | ---------------------------- |
| TCP  | 入站 | 6443*     | Kubernetes API 服务器   | 所有组件                     |
| TCP  | 入站 | 2379-2380 | etcd server client API  | kube-apiserver, etcd         |
| TCP  | 入站 | 10250     | Kubelet API             | kubelet 自身、控制平面组件   |
| TCP  | 入站 | 10251     | kube-scheduler          | kube-scheduler 自身          |
| TCP  | 入站 | 10252     | kube-controller-manager | kube-controller-manager 自身 |

- Node节点需要开放端口

| 协议 | 方向 | 端口范围    | 作用            | 使用者                     |
| ---- | ---- | ----------- | --------------- | -------------------------- |
| TCP  | 入站 | 10250       | Kubelet API     | kubelet 自身、控制平面组件 |
| TCP  | 入站 | 30000-32767 | NodePort 服务** | 所有组件                   |

(内网搭建环境可直接关闭机器防火墙)

```shell
systemctl status firewalld	#查看防火状态 
systemctl stop firewalld	#暂时关闭防火墙 
systemctl disable firewalld	#永久关闭防火墙 
systemctl enable firewalld	#重启防火墙 
```

#### 1.2.3 其他环境依赖

1. 保证机器时区正确一致

   需要保证宿主机器的时区和时间正确一致，如果不一致，使用工具修改：

   ```bash
   sudo timedatectl set-timezone Asia/Shanghai
   
   #修改后，如果想使得系统日志的时间戳也立即生效，则：
   sudo systemctl restart rsyslog 
   ```

2. 确保服务器机器不自动休眠/待机

   系统版本不同，一些默认参数也不同，如果有自动待机，需要关闭

   ```bash
   sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
   ```

3. 保证内核加载了br_netfilter模块

   开启内核 ipv4 转发需要开启br_netfilter模块

   ```bash
   modprobe br_netfilter  #开启该模块
   
   #将以下内容加入/etc/sysctl.d/k8s.conf文件
   cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
   net.bridge.bridge-nf-call-ip6tables = 1
   net.bridge.bridge-nf-call-iptables = 1
   EOF
   sudo sysctl --system
   ```

4. 设置rp_filter的值为0或1

   rp_filter参数用于控制系统是否开启对数据包源地址的校验。k8s的calico中要求这个值为0或1

   0：不开启源地址校验。

   1：开启严格的反向路径校验。对每个进来的数据包，校验其反向路径是否是最佳路径。如果反向路径不是最佳路径，则直接丢弃该数据包。

   2：开启松散的反向路径校验。对每个进来的数据包，校验其源地址是否可达，即反向路径是否能通（通过任意网口），如果反向路径不同，则直接丢弃该数据包。

   ```bash
   #修改/etc/sysctl.d/10-network-security.conf
   sudo vi /etc/sysctl.d/10-network-security.conf
   
   #将下面两个参数的值从2修改为1
   #net.ipv4.conf.default.rp_filter=1
   #net.ipv4.conf.all.rp_filter=1
   
   #然后使之生效
   sudo sysctl --system
   ```


## 2.安装相关工具

### 2.1 安装依赖的工具

安装k8s过程中可能需要使用到的工具软件

直接使用包管理工具进行安装即可

```shell
sudo yum/apt install -y docker.io vim net-tools 
```

### 2.2 安装kubeadmin,kubectl,kubelet(使用阿里源)

需要在每台机器上安装以下的软件包：

- `kubeadm`：用来初始化集群的指令。
- `kubelet`：在集群中的每个节点上用来启动 pod 和容器等。
- `kubectl`：用来与集群通信的命令行工具。

`kubeadmin`工具不会安装`kubectl`和`kubelet`，所以需要自行安装．

#### 2.2.1 Ubuntu/Debian或HypriotOS系统安装命令

```shell
sudo apt-get update && sudo apt-get install -y apt-transport-https curl		#更新包管理工具apt-get并安装一些工具
curl -s https://mirrors.aliyun.com/kubernetes/apt/doc/apt-key.gpg | sudo apt-key add - 	#将|左边的结果作为STDIN(输入流)传递给右边,此处使用的阿里云库(国内有墙访问不了google的apt库)
cat <<EOF | sudo tee /etc/apt/sources.list.d/kubernetes.list
deb https://mirrors.aliyun.com/kubernetes/apt/ kubernetes-xenial main
EOF
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
```

#### 2.2.2	CentOS/RHEL或Fedora系统安装

```shell
#	将EOF中间的内容向/etc/yum.repos.d/kubernetes.repo文件输出
cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg https://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpg
exclude=kube*
EOF

yum install -y kubelet kubeadm kubectl --disableexcludes=kubernetes

systemctl enable --now kubelet
```

注意事项：

- `kubelet`暂时不支持SELinux(SELinux会阻止容器访问宿主机文件系统，容易出错并且难以定位，所以需要关闭)，所以需要先关闭

- 某些centos系统会绕过iptables的路由，而出错.确保 在 `sysctl` 配置中的 `net.bridge.bridge-nf-call-iptables` 被设置为 1

  ```shell
  cat <<EOF >  /etc/sysctl.d/k8s.conf
  net.bridge.bridge-nf-call-ip6tables = 1
  net.bridge.bridge-nf-call-iptables = 1
  EOF
  sysctl --system
  ```

#### 2.2.3 保证Master节点Kubelet的cgroup驱动为cgroupfs

`kubelet`默认的进程管理驱动就是cgroupfs，如果做过改动，则需要手动在`/etc/default/kubelet`文件中修改参数(CentOS等系统是`/etc/sysconfig/kubelet`文件)

```shell
KUBELET_EXTRA_ARGS=--cgroup-driver=<value>  # value为cgroupfs
```

然后重启`kubelet`

```shell
systemctl daemon-reload
systemctl restart kubelet
```

## 3.使用KubeAdmin创建集群

### 3.1 创建Master节点

使用下面命令初始化Master节点，会安装`etcd`（集群数据库）和`API Server`(与`kubectl`交互)

```bash
kubeadm init <args>
```

对于参数的选择，主要有以下几点：

1. (可选)如果计划升级Master为高可用集群，需要指定`--control-plane-endpoint`为所有Master节点设置共享端点，一般为负载均衡器的DNS名称或IP地址.
2. (必须!)安装一个Pod的网络插件(CNI,Container Network Interface),并且根据选择的网络插件，设置`--pod-network-cidr`的值.在该插件安装之前集群DNS(`CoreDNS`)不会启动.
   - `kubeadm`默认及强制使用RBAC(基于角色的访问控制),所以使用的网络插件必须支持RBAC
   - 如果集群使用IPv6，则使用的网络插件也应该支持IPv6
   - 避免Pod网络与主机网络重叠，否则会出现问题
3. (可选)如果安装了多个容器的runtime(多个容器工具),可能需要设置`--cri-socket`参数来指定使用的容器工具(如果有docker则优先使用docker)
4. (可选)除非另有说明,否则`kubeadm`使用默认网管关联的网卡接口设置`API Server`的广播地址.如果想使用其他的网络接口，则需要手动设置`--apiserver-advertise-address=<ip-address>`参数．如果需要使用IPv6地址，则此处需要指定的是IPv6的地址
5. (可选并建议)在`kubeadm init`之前运行`kubeadm config images pull`来验证与gcr.io容器镜像仓库的连通性(此处会先拉拉取需要的镜像来验证是否联通,国内此仓库被墙)

例:

```bash
sudo kubeadm init --pod-network-cidr 10.244.0.0/16  --image-repository registry.cn-hangzhou.aliyuncs.com/google_containers	#指定了一个CIDR(Classless Inter-Domain Routing)，使用阿里云镜像源
```

该命令执行完毕后会拉去镜像，然后输出一条kubeadm join xxx相关命令，并保存下来，如:

```bash
W1116 11:49:31.751435   24225 configset.go:348] WARNING: kubeadm cannot validate component configs for API groups [kubelet.config.k8s.io kubeproxy.config.k8s.io]
[init] Using Kubernetes version: v1.19.4
[preflight] Running pre-flight checks
	[WARNING IsDockerSystemdCheck]: detected "cgroupfs" as the Docker cgroup driver. The recommended driver is "systemd". Please follow the guide at https://kubernetes.io/docs/setup/cri/
[preflight] Pulling images required for setting up a Kubernetes cluster
[preflight] This might take a minute or two, depending on the speed of your internet connection
[preflight] You can also perform this action in beforehand using 'kubeadm config images pull'
[certs] Using certificateDir folder "/etc/kubernetes/pki"
[certs] Generating "ca" certificate and key
[certs] Generating "apiserver" certificate and key
[certs] apiserver serving cert is signed for DNS names [kubernetes kubernetes.default kubernetes.default.svc kubernetes.default.svc.cluster.local llife] and IPs [10.96.0.1 192.168.2.173]
[certs] Generating "apiserver-kubelet-client" certificate and key
[certs] Generating "front-proxy-ca" certificate and key
[certs] Generating "front-proxy-client" certificate and key
[certs] Generating "etcd/ca" certificate and key
[certs] Generating "etcd/server" certificate and key
[certs] etcd/server serving cert is signed for DNS names [llife localhost] and IPs [192.168.2.173 127.0.0.1 ::1]
[certs] Generating "etcd/peer" certificate and key
[certs] etcd/peer serving cert is signed for DNS names [llife localhost] and IPs [192.168.2.173 127.0.0.1 ::1]
[certs] Generating "etcd/healthcheck-client" certificate and key
[certs] Generating "apiserver-etcd-client" certificate and key
[certs] Generating "sa" key and public key
[kubeconfig] Using kubeconfig folder "/etc/kubernetes"
[kubeconfig] Writing "admin.conf" kubeconfig file
[kubeconfig] Writing "kubelet.conf" kubeconfig file
[kubeconfig] Writing "controller-manager.conf" kubeconfig file
[kubeconfig] Writing "scheduler.conf" kubeconfig file
[kubelet-start] Writing kubelet environment file with flags to file "/var/lib/kubelet/kubeadm-flags.env"
[kubelet-start] Writing kubelet configuration to file "/var/lib/kubelet/config.yaml"
[kubelet-start] Starting the kubelet
[control-plane] Using manifest folder "/etc/kubernetes/manifests"
[control-plane] Creating static Pod manifest for "kube-apiserver"
[control-plane] Creating static Pod manifest for "kube-controller-manager"
[control-plane] Creating static Pod manifest for "kube-scheduler"
[etcd] Creating static Pod manifest for local etcd in "/etc/kubernetes/manifests"
[wait-control-plane] Waiting for the kubelet to boot up the control plane as static Pods from directory "/etc/kubernetes/manifests". This can take up to 4m0s
[apiclient] All control plane components are healthy after 14.502569 seconds
[upload-config] Storing the configuration used in ConfigMap "kubeadm-config" in the "kube-system" Namespace
[kubelet] Creating a ConfigMap "kubelet-config-1.19" in namespace kube-system with the configuration for the kubelets in the cluster
[upload-certs] Skipping phase. Please see --upload-certs
[mark-control-plane] Marking the node llife as control-plane by adding the label "node-role.kubernetes.io/master=''"
[mark-control-plane] Marking the node llife as control-plane by adding the taints [node-role.kubernetes.io/master:NoSchedule]
[bootstrap-token] Using token: b06erx.bqoobaetxh4velwm
[bootstrap-token] Configuring bootstrap tokens, cluster-info ConfigMap, RBAC Roles
[bootstrap-token] configured RBAC rules to allow Node Bootstrap tokens to get nodes
[bootstrap-token] configured RBAC rules to allow Node Bootstrap tokens to post CSRs in order for nodes to get long term certificate credentials
[bootstrap-token] configured RBAC rules to allow the csrapprover controller automatically approve CSRs from a Node Bootstrap Token
[bootstrap-token] configured RBAC rules to allow certificate rotation for all node client certificates in the cluster
[bootstrap-token] Creating the "cluster-info" ConfigMap in the "kube-public" namespace
[kubelet-finalize] Updating "/etc/kubernetes/kubelet.conf" to point to a rotatable kubelet client certificate and key
[addons] Applied essential addon: CoreDNS
[addons] Applied essential addon: kube-proxy

Your Kubernetes control-plane has initialized successfully!

To start using your cluster, you need to run the following as a regular user:

  #执行下列命令给非sudo用户执行kubectl的权限
  mkdir -p $HOME/.kube			
  sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  sudo chown $(id -u):$(id -g) $HOME/.kube/config
  
  KUBECONFIG=/etc/kubernetes/kubelet.conf

You should now deploy a pod network to the cluster.
Run "kubectl apply -f [podnetwork].yaml" with one of the options listed at:
  https://kubernetes.io/docs/concepts/cluster-administration/addons/

Then you can join any number of worker nodes by running the following on each as root:
    
    kubeadm join 192.168.2.173:6443 --token vg1u1e.wx5bycpfjx4p8zbc \
    --discovery-token-ca-cert-hash sha256:cff7de99d2f15b0389e689b58a16b90b682cf24632761f1384aab8f16253c97b #该命令为Node节点加入集群执行的命令
```

### 3.2 在Master节点上安装网络插件

在init后,执行kubectl get pods --all-namespaces可以看到coredns容器会一直处于pending状态等待网络插件安装.

下面示例为网络插件calico的安装:

```bash
#部署calico
https://docs.projectcalico.org/v3.3/getting-started/kubernetes/installation/hosted/kubernetes-datastore/calico-networking/1.7/calico.yaml

vim calico.yaml

1）修改ipip模式关闭 和typha_service_name

modprobe -r ipip #删除tunl0网络

- name: CALICO_IPV4POOL_IPIP
value: "off"


typha_service_name: "calico-typha"




calico网络，默认是ipip模式（在每台node主机创建一个tunl0网口，这个隧道链接所有的node容器网络，官网推荐不同的ip网段适合，比如aws的不同区域主机），

修改成BGP模式，它会以daemonset方式安装在所有node主机，每台主机启动一个bird(BGP client)，它会将calico网络内的所有node分配的ip段告知集群内的主机，并通过本机的网卡eth0或者ens33转发数据；

2）修改replicas

  replicas: 1
  revisionHistoryLimit: 2

3）修改pod的网段CALICO_IPV4POOL_CIDR

- name: CALICO_IPV4POOL_CIDR
value: "10.244.0.0/16"
4）如果手动下载镜像请查看calico.yaml 文件里面标注的镜像版本 否则可以直接执行会自动下载
5）部署calico
kubectl apply -f calico.yaml

6）查看
kubectl get po --all-namespaces
此时你会发现是pending状态是因为node节点还没有相关组件
7） 验证是否为bgp模式
# ip route show
default via 172.31.143.253 dev eth0 
blackhole 10.244.0.0/24 proto bird 
10.244.0.2 dev caliac6de7553e8 scope link 
10.244.0.3 dev cali1591fcccf0f scope link 
10.244.1.0/24 via 172.31.135.237 dev eth0 proto bird 
10.244.2.0/24 via 172.31.135.238 dev eth0 proto bird 
169.254.0.0/16 dev eth0 scope link metric 1002 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 
172.31.128.0/20 dev eth0 proto kernel scope link src 172.31.135.239 

```

然后等带所有的pod都为running状态则Master机器部署成功.(如果此时只有node和calico-controller的pod处于pendding状态，表示集群正在等带节点加入，至少一个节点加入集群状态才为正常)

### 3.3 创建Node节点

节点上只需要执行kubeadm join即可加入集群，如：

```bash
kubeadm join 192.168.2.173:6443 --token vg1u1e.wx5bycpfjx4p8zbc \
    --discovery-token-ca-cert-hash sha256:cff7de99d2f15b0389e689b58a16b90b682cf24632761f1384aab8f16253c97b
```

### 3.4 在Master节点上部署官方Dashboard(K8S-UI)

在Master节点上执行命令即可部署官方的Dashboard，但是只能在该节点访问

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.4/aio/deploy/recommended.yaml
```

使用kubectl get pods -A查看部署情况，当dashboard的pod状态正常时，执行kubectl proxy即可访问[dashboard](http://localhost:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/)

如果想要访问dashboard,则需要先创建一个用户:

```bash
#创建一个ServiceAccount
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kubernetes-dashboard
EOF

#创建一个ClusterRoleBinding
cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kubernetes-dashboard
EOF

#获取登录Token
kubectl -n kubernetes-dashboard describe secret $(kubectl -n kubernetes-dashboard get secret | grep admin-user | awk '{print $1}')

Name:         admin-user-token-v57nw
Namespace:    kubernetes-dashboard
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: admin-user
              kubernetes.io/service-account.uid: 0303243c-4040-4a58-8a47-849ee9ba79c1

Type:  kubernetes.io/service-account-token

Data
====
ca.crt:     1066 bytes
namespace:  20 bytes
token:      eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlcm5ldGVzLWRhc2hib2FyZCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJhZG1pbi11c2VyLXRva2VuLXY1N253Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImFkbWluLXVzZXIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIwMzAzMjQzYy00MDQwLTRhNTgtOGE0Ny04NDllZTliYTc5YzEiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZXJuZXRlcy1kYXNoYm9hcmQ6YWRtaW4tdXNlciJ9.Z2JrQlitASVwWbc-s6deLRFVk5DWD3P_vjUFXsqVSY10pbjFLG4njoZwh8p3tLxnX_VBsr7_6bwxhWSYChp9hwxznemD5x5HLtjb16kI9Z7yFWLtohzkTwuFbqmQaMoget_nYcQBUC5fDmBHRfFvNKePh_vSSb2h_aYXa8GV5AcfPQpY7r461itme1EXHQJqv-SN-zUnguDguCTjD80pFZ_CmnSE1z9QdMHPB8hoB4V68gtswR1VLa6mSYdgPwCHauuOobojALSaMc3RH7MmFUumAgguhqAkX3Omqd3rJbYOMRuMjhANqd08piDC3aIabINX6gP5-Tuuw2svnV6NYQ  #这个为访问网站时登录的Token

#删除创建的东西
kubectl -n kubernetes-dashboard delete serviceaccount admin-user
kubectl -n kubernetes-dashboard delete clusterrolebinding admin-user
```

## 4.清理集群节点

### 4.1 删除Node节点

​	如果想要删除一个工作节点，需要重置在工作节点处对kubeadm的安装状态后，在Master节点删除节点信息

```bash
#在worker节点执行
kubeadm reset

#在master节点执行
kubectl drain <node name> --delete-local-data --force --ignore-daemonsets
```

### 4.2 删除Master节点

​	想要完全删除Master节点就需要删除集群有关的数据

```bash
kubectl config delete-cluster kubernetes
#使用kubeadm删除集群数据
kubeadm reset

#手动删除集群残留数据
rm -rf /etc/kubernetes
rm -rf $HOME/.kube
rm -rf /etc/cni/net.d
rm -rf /var/lib/etcd
iptables -F && iptables -t nat -F && iptables -t mangle -F && iptables -X
ipvsadm -C
rm -rf /var/lib/cni

```



## 5.使用集群部署一个应用Pod

### 5.1 使用kubectl部署Pod

一般使用 yaml(或 json)来描述发布配置. 下面是一个简单的描述文件: `nginx-pod.yaml`

```yaml
apiVersion: v1      # 描述文件所遵循 KubernetesAPI 的版本
kind: Pod           # 描述的类型是 pod
metadata:
  name: nginx-pod   # pod 的名称
  labels:           # 标签
    app: nginx-pod
    env: test
spec:
  containers:
    - name: nginx-pod     # 容器名
      image: nginx:1.18   # 镜像名称及版本
      imagePullPolicy: IfNotPresent   # 如果本地不存在就去远程仓库拉取
      ports:
        - containerPort: 80   # pod 对外端口
  restartPolicy: Always
```

在Master机器上执行以下命令:

```bash
kubectl apply -f nginx-pod.yaml

kubectl get pods			#检查Pod状态
NAME        READY   STATUS    RESTARTS   AGE
nginx-pod   1/1     Running   0          39s
```

### 5.2 使用Dashboard部署Pod

将yaml文件输入并上传即可创建Pod

![image-20201117120027497](/home/zou/.config/Typora/typora-user-images/image-20201117120027497.png)

### 5.3 访问这个nginx应用

此时部署的Pod并不能访问，需要通过端口转发才能访问.下面命令使用宿主机的9999端口进行转发

```bash
kubectl port-forward --address 0.0.0.0 nginx-pod 9999:80
Forwarding from 0.0.0.0:9999 -> 80
Handling connection for 9999
```

### 5.4 将服务暴露给外部客户端的几种方式

- 通过 `port-forward` 转发, 这种方式操作方便、适合调试时使用, **不适用于生产环境** .
- 通过 `NodePort`, 此时集群中每一个节点 (Node) 都会监听指定端口, 我们通过任意节点的端口即可访问到指定服务. 但过多的服务会开启大量端口难以维护.
- 通过 `LoadBalance` 来暴露服务. `LoadBalance(负载均衡 LB)` 通常由云服务商提供, 如果云环境中不提供 LB 服务, 我们通常直接使用 `Ingress`, 或使用 `MetalLB` 来自行配置 LB.
- 通过 `Ingress` 公开多个服务. `Ingress` 公开了从群集外部到群集内 `services` 的 HTTP 和 HTTPS 路由. 流量路由由 `Ingress` 资源上定义的规则控制. 在云服务商不提供 LB 服务的情况下, 我们可以直接使用 `Ingress` 来暴露服务. (另外, 使用 `LB + Ingress` 的部署方案可以避免过多 LB 应用带来的花费).