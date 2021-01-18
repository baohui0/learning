# Kubeadm源码导读

kubeadm作为官方引导集群的软件，可以通过阅读该模块了解到k8s启动的流程

```go
//下图代码在cmd/kubeadm/app/cmd/cmd.go文件中，作为kubeadm命令入口

cmds.AddCommand(newCmdCompletion(out, ""))		//对应kubeadm completion
cmds.AddCommand(newCmdConfig(out))				//对应kubeadm config
cmds.AddCommand(newCmdInit(out, nil))			//对应kubeadm init
cmds.AddCommand(newCmdJoin(out, nil))			//对应kubeadm join
cmds.AddCommand(newCmdReset(in, out, nil))		//对应kubeadm reset
cmds.AddCommand(newCmdVersion(out))				//对应kubeadm version
cmds.AddCommand(newCmdToken(out, err))			//对应kubeadm token
cmds.AddCommand(upgrade.NewCmdUpgrade(out))		//对应kubeadm upgrade
cmds.AddCommand(alpha.NewCmdAlpha(in, out))		//对应kubeadm alpha
options.AddKubeadmOtherFlags(cmds.PersistentFlags(), &rootfsPath)	

cmds.AddCommand(alpha.NewCmdCertsUtility(out))	//对应kubeadm certs
```

## Kubeadm init命令

kubeadm init命令用于引导master节点

```go
	//下列代码在kubernetes/cmd/kubeadm/app/cmd/init.go中

	//用于将命令行参数解析到cfg对象中
	AddInitConfigFlags(cmd.Flags(), initOptions.externalInitCfg)
	AddClusterConfigFlags(cmd.Flags(), initOptions.externalClusterCfg, &initOptions.featureGatesString)
	AddInitOtherFlags(cmd.Flags(), initOptions)
	initOptions.bto.AddTokenFlag(cmd.Flags())
	initOptions.bto.AddTTLFlag(cmd.Flags())
	options.AddImageMetaFlags(cmd.Flags(), &initOptions.externalClusterCfg.ImageRepository)

	//初始化一些cfg参数
	initRunner.SetAdditionalFlags(func(flags *flag.FlagSet) {
		options.AddKubeConfigFlag(flags, &initOptions.kubeconfigPath)
		options.AddKubeConfigDirFlag(flags, &initOptions.kubeconfigDir)
		options.AddControlPlanExtraArgsFlags(flags, &initOptions.externalClusterCfg.APIServer.ExtraArgs, &initOptions.externalClusterCfg.ControllerManager.ExtraArgs, &initOptions.externalClusterCfg.Scheduler.ExtraArgs)
	})

	//init流程，各阶段构建
	initRunner.AppendPhase(phases.NewPreflightPhase())			//飞行前检查，主要执行NodeCheck和ImageCheck
	initRunner.AppendPhase(phases.NewCertsPhase())	 			//
	initRunner.AppendPhase(phases.NewKubeConfigPhase())
	initRunner.AppendPhase(phases.NewKubeletStartPhase())
	initRunner.AppendPhase(phases.NewControlPlanePhase())
	initRunner.AppendPhase(phases.NewEtcdPhase())
	initRunner.AppendPhase(phases.NewWaitControlPlanePhase())
	initRunner.AppendPhase(phases.NewUploadConfigPhase())
	initRunner.AppendPhase(phases.NewUploadCertsPhase())
	initRunner.AppendPhase(phases.NewMarkControlPlanePhase())
	initRunner.AppendPhase(phases.NewBootstrapTokenPhase())
	initRunner.AppendPhase(phases.NewKubeletFinalizePhase())
	initRunner.AppendPhase(phases.NewAddonPhase())

	
	initRunner.SetDataInitializer(func(cmd *cobra.Command, args []string) (workflow.RunData, error) {
		return newInitData(cmd, args, initOptions, out)
	})
```

### PreflightPhase飞行前阶段检查

飞行前阶段主要检查两件事，一个是InitNodeCheck，代码如下：

```go
func RunInitNodeChecks(execer utilsexec.Interface, cfg *kubeadmapi.InitConfiguration, ignorePreflightErrors sets.String, isSecondaryControlPlane bool, downloadCerts bool) error {
	if !isSecondaryControlPlane {
		//首先检测是否root权限
		if err := RunRootCheckOnly(ignorePreflightErrors); err != nil {
			return err
		}
	}
	
    //获取/etc/kubernetes/manifests的清单目录
	manifestsDir := filepath.Join(kubeadmconstants.KubernetesDir, kubeadmconstants.ManifestsSubDirName)
    //下列代码创建检查项列表
	checks := []Checker{
		NumCPUCheck{NumCPU: kubeadmconstants.ControlPlaneNumCPU},		//检查CPU核数是否少于2
		MemCheck{Mem: kubeadmconstants.ControlPlaneMem},				//检查内存大小是否少于1700M
		KubernetesVersionCheck{KubernetesVersion: cfg.KubernetesVersion, KubeadmVersion: kubeadmversion.Get().GitVersion}, //k8s版本号检测
		FirewalldCheck{ports: []int{int(cfg.LocalAPIEndpoint.BindPort), kubeadmconstants.KubeletPort}},	//防火墙检测
		PortOpenCheck{port: int(cfg.LocalAPIEndpoint.BindPort)},	//端口检测
		PortOpenCheck{port: kubeadmconstants.KubeSchedulerPort},	//端口检测
		PortOpenCheck{port: kubeadmconstants.KubeControllerManagerPort},	//端口检测
		FileAvailableCheck{Path: kubeadmconstants.GetStaticPodFilepath(kubeadmconstants.KubeAPIServer, manifestsDir)},	//APIServer的yaml文件可用检测
		FileAvailableCheck{Path: kubeadmconstants.GetStaticPodFilepath(kubeadmconstants.KubeControllerManager, manifestsDir)},	//controller-manager的yaml文件可用检测
		FileAvailableCheck{Path: kubeadmconstants.GetStaticPodFilepath(kubeadmconstants.KubeScheduler, manifestsDir)},	//kube-scheduler的yaml文件可用检测
		FileAvailableCheck{Path: kubeadmconstants.GetStaticPodFilepath(kubeadmconstants.Etcd, manifestsDir)},	//etcd的yaml文件可用检测
		HTTPProxyCheck{Proto: "https", Host: cfg.LocalAPIEndpoint.AdvertiseAddress},	//https代理可用检测
	}
    //service子网可用检测
	cidrs := strings.Split(cfg.Networking.ServiceSubnet, ",")
	for _, cidr := range cidrs {
		checks = append(checks, HTTPProxyCIDRCheck{Proto: "https", CIDR: cidr})
	}
    //pod子网可用检测
	cidrs = strings.Split(cfg.Networking.PodSubnet, ",")
	for _, cidr := range cidrs {
		checks = append(checks, HTTPProxyCIDRCheck{Proto: "https", CIDR: cidr})
	}

	if !isSecondaryControlPlane {
		checks = addCommonChecks(execer, cfg.KubernetesVersion, &cfg.NodeRegistration, checks)

        //检查是否设置了Bridge-netfilter和IPv6可用
		if ip := net.ParseIP(cfg.LocalAPIEndpoint.AdvertiseAddress); ip != nil {
			if utilsnet.IsIPv6(ip) {
				checks = append(checks,
					FileContentCheck{Path: bridgenf6, Content: []byte{'1'}},
					FileContentCheck{Path: ipv6DefaultForwarding, Content: []byte{'1'}},
				)
			}
		}

		//如果使用外部etcd服务，检测外部etcd版本
		if cfg.Etcd.External != nil {
			// Check external etcd version before creating the cluster
			checks = append(checks, ExternalEtcdVersionCheck{Etcd: cfg.Etcd})
		}
	}
	//如果使用本地etcd服务，增加检测项
	if cfg.Etcd.Local != nil {
		checks = append(checks,
			PortOpenCheck{port: kubeadmconstants.EtcdListenClientPort},
			PortOpenCheck{port: kubeadmconstants.EtcdListenPeerPort},
			DirAvailableCheck{Path: cfg.Etcd.Local.DataDir},
		)
	}
	//检测etcd服务的三个证书相关文件
	if cfg.Etcd.External != nil && !(isSecondaryControlPlane && downloadCerts) {
		// Only check etcd certificates when using an external etcd and not joining with automatic download of certs
		if cfg.Etcd.External.CAFile != "" {
			checks = append(checks, FileExistingCheck{Path: cfg.Etcd.External.CAFile, Label: "ExternalEtcdClientCertificates"})
		}
		if cfg.Etcd.External.CertFile != "" {
			checks = append(checks, FileExistingCheck{Path: cfg.Etcd.External.CertFile, Label: "ExternalEtcdClientCertificates"})
		}
		if cfg.Etcd.External.KeyFile != "" {
			checks = append(checks, FileExistingCheck{Path: cfg.Etcd.External.KeyFile, Label: "ExternalEtcdClientCertificates"})
		}
	}
	//根据检测项执行检测
	return RunChecks(checks, os.Stderr, ignorePreflightErrors)
}
```

另一个是ImageCheck，代码如下：

```go
func RunPullImagesCheck(execer utilsexec.Interface, cfg *kubeadmapi.InitConfiguration, ignorePreflightErrors sets.String) error {
    //构建容器运行时
	containerRuntime, err := utilruntime.NewContainerRuntime(utilsexec.New(), cfg.NodeRegistration.CRISocket)
	if err != nil {
		return err
	}
	//添加镜像检查
	checks := []Checker{
		ImagePullCheck{runtime: containerRuntime, imageList: images.GetControlPlaneImages(&cfg.ClusterConfiguration)},
	}
	return RunChecks(checks, os.Stderr, ignorePreflightErrors)
}
```

### NewCertsPhase证书阶段检查



```go

```

