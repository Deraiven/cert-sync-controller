package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Deraiven/cert-controller/internal/config"
	"github.com/Deraiven/cert-controller/internal/controller"
	"github.com/Deraiven/cert-controller/internal/kong"
	certmanagerclientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	"gopkg.in/yaml.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

func main() {
	var configFile string
	var kubeconfig string
	var healthAddr string

	flag.StringVar(&configFile, "config", "config/config.yaml", "Path to configuration file")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	flag.StringVar(&healthAddr, "health-addr", ":8080", "Health check address")
	flag.Parse()

	// 设置 klog
	klog.InitFlags(nil)
	defer klog.Flush()

	// 加载配置
	cfg, err := loadConfig(configFile)
	if err != nil {
		klog.Fatalf("Failed to load config: %v", err)
	}

	// 创建 Kubernetes 客户端
	k8sConfig, err := getK8sConfig(kubeconfig)
	if err != nil {
		klog.Fatalf("Failed to get k8s config: %v", err)
	}

	kubeClient, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		klog.Fatalf("Failed to create k8s client: %v", err)
	}

	// 创建 cert-manager 客户端
	certManagerClient, err := certmanagerclientset.NewForConfig(k8sConfig)
	if err != nil {
		klog.Fatalf("Failed to create cert-manager client: %v", err)
	}

	// 创建 Kong 客户端
	kongClient := kong.NewClient(cfg.Kong.AdminURL, cfg.Kong.AdminToken)

	// 创建控制器
	certController := controller.NewCertificateController(
		kubeClient,
		certManagerClient,
		kongClient,
		cfg,
	)

	// 启动健康检查服务器
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := &http.Server{
		Addr:    healthAddr,
		Handler: mux,
	}

	go func() {
		klog.Infof("Starting health check server on %s", healthAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			klog.Errorf("Health check server error: %v", err)
		}
	}()

	// 设置信号处理
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 优雅关闭
	go func() {
		<-sigCh
		klog.Info("Received termination signal, shutting down...")

		// 关闭 HTTP 服务器
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			klog.Errorf("HTTP server shutdown error: %v", err)
		}

		// 取消控制器
		cancel()
	}()

	// 运行控制器
	if err := certController.Run(ctx); err != nil {
		klog.Fatalf("Controller error: %v", err)
	}

	klog.Info("Controller stopped gracefully")
}

func loadConfig(filePath string) (*config.Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// 设置默认值
	if cfg.Controller.WatchNamespace == "" {
		cfg.Controller.WatchNamespace = "cert-manager"
	}
	if cfg.Controller.ResyncPeriod == 0 {
		cfg.Controller.ResyncPeriod = 30 * time.Minute
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "text"
	}

	return &cfg, nil
}

func getK8sConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()

	// 2. 尝试根据这些规则构建配置
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	config, err := kubeConfig.ClientConfig()
	if err == nil {
		return config, nil
	}

	return rest.InClusterConfig()
}
