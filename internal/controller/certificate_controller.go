package controller

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Deraiven/cert-controller/internal/config"
	"github.com/Deraiven/cert-controller/internal/kong"
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	certmanagerclientset "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	certmanagerinformer "github.com/cert-manager/cert-manager/pkg/client/informers/externalversions"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

type CertificateController struct {
	kubeClient        kubernetes.Interface
	certManagerClient certmanagerclientset.Interface
	kongClient        *kong.Client
	config            *config.Config

	syncQueue           workqueue.RateLimitingInterface
	certificateInformer cache.SharedIndexInformer
	secretInformer      cache.SharedIndexInformer
}

func NewCertificateController(
	kubeClient kubernetes.Interface,
	certManagerClient certmanagerclientset.Interface,
	kongClient *kong.Client,
	config *config.Config,
) *CertificateController {
	controller := &CertificateController{
		kubeClient:        kubeClient,
		certManagerClient: certManagerClient,
		kongClient:        kongClient,
		config:            config,
		syncQueue: workqueue.NewNamedRateLimitingQueue(
			workqueue.DefaultControllerRateLimiter(),
			"certificates",
		),
	}

	return controller
}

func (c *CertificateController) Run(ctx context.Context) error {
	klog.Info("=== Starting Kong Certificate Sync Controller ===")

	klog.Infof("Configuration:")
	klog.Infof("  - Watch namespace: %s", c.config.Controller.WatchNamespace)
	klog.Infof("  - Label selector: %s", c.config.Controller.LabelSelector)
	klog.Infof("  - Kong Admin URL: %s", c.config.Kong.AdminURL)
	klog.Infof("  - Cluster name: %s", c.config.Controller.ClusterName)

	klog.Info("Testing Kong connection...")
	if err := c.kongClient.ValidateConnection(); err != nil {
		klog.Errorf("Failed to connect to Kong: %v", err)
		return err
	}

	klog.Info("Getting initial Kong certificate status...")
	initialCount, err := c.kongClient.GetCertificateCount()
	if err != nil {
		klog.Warningf("Failed to get initial certificate count: %v", err)
	} else {
		klog.Infof("Kong currently has %d certificates", initialCount)
	}

	klog.Infof("Checking certificates in namespace %s...", c.config.Controller.WatchNamespace)
	certificates, err := c.certManagerClient.CertmanagerV1().Certificates(c.config.Controller.WatchNamespace).List(
		context.Background(),
		metav1.ListOptions{},
	)
	if err != nil {
		klog.Warningf("Failed to list certificates: %v", err)
	} else {
		klog.Infof("Found %d certificates in namespace %s:", len(certificates.Items), c.config.Controller.WatchNamespace)

		for i, cert := range certificates.Items {
			status := "Not Ready"
			if c.isCertificateReady(&cert) {
				status = "Ready"
			}

			snis := c.getCertificateSNIs(&cert)
			klog.Infof("  [%d] %s:", i+1, cert.Name)
			klog.Infof("      Status: %s", status)
			klog.Infof("      Secret: %s", cert.Spec.SecretName)
			klog.Infof("      SNIs: %v", snis)
			klog.Infof("      Labels: %v", cert.Labels)
		}
	}

	certFactory := certmanagerinformer.NewSharedInformerFactoryWithOptions(
		c.certManagerClient,
		c.config.Controller.ResyncPeriod,
		certmanagerinformer.WithNamespace(c.config.Controller.WatchNamespace),
	)

	kubeFactory := informers.NewSharedInformerFactoryWithOptions(
		c.kubeClient,
		c.config.Controller.ResyncPeriod,
		informers.WithNamespace(c.config.Controller.WatchNamespace),
	)

	c.certificateInformer = certFactory.Certmanager().V1().Certificates().Informer()
	const secretNameIndex = "spec.secretName"
	err = c.certificateInformer.AddIndexers(cache.Indexers{
		secretNameIndex: func(obj interface{}) ([]string, error) {
			cert, ok := obj.(*certmanagerv1.Certificate)
			if !ok {
				return []string{}, nil
			}
			if cert.Spec.SecretName == "" {
				return []string{}, nil
			}
			// 索引键为 Secret 的名字
			return []string{cert.Spec.SecretName}, nil
		},
	})

	if err != nil {
		klog.Fatalf("Failed to add indexer: %v", err)
	}
	c.secretInformer = kubeFactory.Core().V1().Secrets().Informer()

	c.certificateInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onCertificateAdd,
		UpdateFunc: c.onCertificateUpdate,
		DeleteFunc: c.onCertificateDelete,
	})

	c.secretInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onSecretAdd,
		UpdateFunc: c.onSecretUpdate,
		DeleteFunc: c.onSecretDelete,
	})

	certFactory.Start(ctx.Done())
	kubeFactory.Start(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(),
		c.certificateInformer.HasSynced,
		c.secretInformer.HasSynced,
	) {
		return fmt.Errorf("failed to sync caches")
	}

	for i := 0; i < 3; i++ {
		go wait.Until(c.runWorker, time.Second, ctx.Done())
	}

	go c.monitorKongCertificates(ctx)

	klog.Info("✅ Controller started successfully")
	<-ctx.Done()
	klog.Info("🛑 Controller shutting down...")
	return nil
}

func (c *CertificateController) onCertificateAdd(obj interface{}) {
	cert := obj.(*certmanagerv1.Certificate)

	// klog.Infof("Certificate added: %s/%s", cert.Namespace, cert.Name)

	if !c.shouldSync(cert) {
		return
	}

	key := c.getQueueKey(cert.Namespace, cert.Name, "certificate")
	klog.Infof("Certificate added: %s/%s", cert.Namespace, cert.Name)
	c.syncQueue.Add(key)
}

func (c *CertificateController) onCertificateUpdate(oldObj, newObj interface{}) {
	oldCert := oldObj.(*certmanagerv1.Certificate)
	newCert := newObj.(*certmanagerv1.Certificate)

	if !c.certificateChanged(oldCert, newCert) {
		return
	}

	if !c.shouldSync(newCert) {
		return
	}

	key := c.getQueueKey(newCert.Namespace, newCert.Name, "certificate")
	klog.Infof("Certificate updated: %s/%s", newCert.Namespace, newCert.Name)
	c.syncQueue.Add(key)
}

func (c *CertificateController) onCertificateDelete(obj interface{}) {
	cert, ok := obj.(*certmanagerv1.Certificate)
	// _ = c.kubeClient.CoreV1().Secrets(cert.Namespace).Delete(context.Background(), cert.Spec.SecretName, metav1.DeleteOptions{})

	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Couldn't get object from tombstone %#v", obj)
			return
		}
		cert, ok = tombstone.Obj.(*certmanagerv1.Certificate)
		if !ok {
			klog.Errorf("Tombstone contained object that is not a Certificate: %#v", tombstone.Obj)
			return
		}
	}

	if !c.shouldSync(cert) {
		return
	}

	snis := c.getCertificateSNIs(cert)
	if len(snis) == 0 {
		klog.Warningf("Certificate %s/%s has no SNIs, cannot delete from Kong", cert.Namespace, cert.Name)
		return
	}

	klog.Infof("Deleting certificate %s/%s from Kong (SNIs: %v)", cert.Namespace, cert.Name, snis)
	err := c.kongClient.DeleteCertificateBySNIs(snis)
	if err != nil {
		klog.Error("Cannot find certificate %s from kong", cert.Name)
		return
	}
	// key := c.getQueueKey(cert.Namespace, cert.Name, "certificate-delete")
	klog.Infof("Certificate deleted: %s/%s", cert.Namespace, cert.Name)
	// c.syncQueue.Add(key)
}

func (c *CertificateController) onSecretAdd(obj interface{}) {
	secret := obj.(*corev1.Secret)

	if secret.Type != corev1.SecretTypeTLS {
		return
	}

	cert := c.findCertificateBySecretName(secret.Namespace, secret.Name)
	if cert == nil || !c.shouldSync(cert) {
		return
	}

	key := c.getQueueKey(cert.Namespace, cert.Name, "secret")
	klog.V(2).Infof("TLS Secret added: %s/%s (cert: %s)", secret.Namespace, secret.Name, cert.Name)
	c.syncQueue.Add(key)
}

func (c *CertificateController) onSecretUpdate(oldObj, newObj interface{}) {
	oldSecret := oldObj.(*corev1.Secret)
	newSecret := newObj.(*corev1.Secret)

	if newSecret.Type != corev1.SecretTypeTLS {
		return
	}

	if !c.secretDataChanged(oldSecret, newSecret) {
		return
	}

	cert := c.findCertificateBySecretName(newSecret.Namespace, newSecret.Name)
	if cert == nil || !c.shouldSync(cert) {
		return
	}

	key := c.getQueueKey(cert.Namespace, cert.Name, "secret")
	klog.Infof("TLS Secret updated: %s/%s (cert: %s)", newSecret.Namespace, newSecret.Name, cert.Name)
	c.syncQueue.Add(key)
}

func (c *CertificateController) onSecretDelete(obj interface{}) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.Errorf("Couldn't get object from tombstone %#v", obj)
			return
		}
		secret, ok = tombstone.Obj.(*corev1.Secret)
		if !ok {
			klog.Errorf("Tombstone contained object that is not a Secret: %#v", tombstone.Obj)
			return
		}
	}

	if secret.Type != corev1.SecretTypeTLS {
		return
	}

	cert := c.findCertificateBySecretName(secret.Namespace, secret.Name)
	if cert == nil || !c.shouldSync(cert) {
		return
	}

	key := c.getQueueKey(cert.Namespace, cert.Name, "secret-delete")
	klog.Infof("TLS Secret deleted: %s/%s (cert: %s)", secret.Namespace, secret.Name, cert.Name)
	c.syncQueue.Add(key)
}

func (c *CertificateController) syncHandler(key string) error {
	namespace, name, eventType, err := c.parseQueueKey(key)
	if err != nil {
		klog.Errorf("Failed to parse queue key %s: %v", key, err)
		return nil
	}

	switch eventType {
	case "certificate", "secret":
		return c.syncCertificateToKong(namespace, name)
	case "certificate-delete":
		return c.deleteCertificateFromKong(namespace, name)
	case "secret-delete":
		cert := c.findCertificateBySecretName(namespace, name)
		if cert != nil {
			klog.Warningf("Secret %s/%s deleted but certificate still exists", namespace, name)
			return nil
		}
		return c.deleteCertificateFromKong(namespace, name)
	default:
		return fmt.Errorf("unknown event type: %s", eventType)
	}
}

func (c *CertificateController) syncCertificateToKong(namespace, name string) error {
	cert, err := c.certManagerClient.CertmanagerV1().Certificates(namespace).Get(
		context.Background(),
		name,
		metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to get certificate: %v", err)
	}

	klog.Infof("Processing certificate %s/%s (Secret: %s, Ready: %v)",
		namespace, name, cert.Spec.SecretName, c.isCertificateReady(cert))

	if !c.shouldSync(cert) {
		klog.V(2).Infof("Skipping certificate %s/%s (not ready or filtered)", namespace, name)
		return nil
	}

	secretName := cert.Spec.SecretName
	secret, err := c.kubeClient.CoreV1().Secrets(namespace).Get(
		context.Background(),
		secretName,
		metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to get secret %s: %v", secretName, err)
	}

	klog.V(2).Infof("Found secret %s/%s (type: %s)", namespace, secretName, secret.Type)

	if err := c.validateSecret(secret); err != nil {
		return fmt.Errorf("invalid secret: %v", err)
	}

	// klog.Infof("DEBUG: full secret object: %+v", secret)

	certData, keyData, err := c.getSecretData(secret)
	if err != nil {
		return fmt.Errorf("failed to decode secret data: %v", err)
	}

	klog.V(3).Infof("Certificate data length: %d bytes, Key data length: %d bytes",
		len(certData), len(keyData))

	snis := c.getCertificateSNIs(cert)
	if len(snis) == 0 {
		return fmt.Errorf("certificate %s/%s has no DNS names", namespace, name)
	}

	klog.V(2).Infof("Certificate %s/%s has SNIs: %v", namespace, name, snis)

	if !c.validateCertificateFormat(certData) {
		return fmt.Errorf("invalid certificate format in secret %s", secretName)
	}

	if !c.validatePrivateKeyFormat(keyData) {
		return fmt.Errorf("invalid private key format in secret %s", secretName)
	}

	kongCert := &kong.Certificate{
		Cert: certData,
		Key:  keyData,
		SNIs: snis,
		Tags: c.generateTags(namespace, name, cert),
	}

	klog.Infof("Syncing certificate %s/%s to Kong with %d SNIs", namespace, name, len(snis))
	if err := c.kongClient.CreateOrUpdateCertificate(kongCert); err != nil {
		return fmt.Errorf("failed to sync certificate to Kong: %v", err)
	}

	klog.Infof("Successfully synced certificate %s/%s with SNIs: %v", namespace, name, snis)
	return nil
}

func (c *CertificateController) getSecretData(secret *corev1.Secret) (string, string, error) {
	certBytes, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return "", "", fmt.Errorf("secret does not contain %s key", corev1.TLSCertKey)
	}
	// klog.Infof("certdata is %s", certBase64)

	keyBytes, ok := secret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return "", "", fmt.Errorf("secret does not contain %s key", corev1.TLSPrivateKeyKey)
	}
	// klog.Infof("key data is %s", keyBase64)
	// certBytes, err := base64.StdEncoding.DecodeString(string(certBase64))
	// if err != nil {
	// 	return "", "", fmt.Errorf("failed to decode certificate: %v", err)
	// }

	// keyBytes, err := base64.StdEncoding.DecodeString(string(keyBase64))
	// if err != nil {
	// 	return "", "", fmt.Errorf("failed to decode private key: %v", err)
	// }

	certData := strings.TrimSpace(string(certBytes))
	keyData := strings.TrimSpace(string(keyBytes))

	return certData, keyData, nil
}

func (c *CertificateController) validateCertificateFormat(certData string) bool {
	if !strings.Contains(certData, "-----BEGIN CERTIFICATE-----") {
		klog.Errorf("Certificate missing BEGIN CERTIFICATE header")
		return false
	}

	if !strings.Contains(certData, "-----END CERTIFICATE-----") {
		klog.Errorf("Certificate missing END CERTIFICATE header")
		return false
	}

	return true
}

func (c *CertificateController) validatePrivateKeyFormat(keyData string) bool {
	hasValidHeader := strings.Contains(keyData, "-----BEGIN PRIVATE KEY-----") ||
		strings.Contains(keyData, "-----BEGIN RSA PRIVATE KEY-----") ||
		strings.Contains(keyData, "-----BEGIN EC PRIVATE KEY-----")

	if !hasValidHeader {
		klog.Errorf("Private key missing valid BEGIN header")
		return false
	}

	hasValidFooter := strings.Contains(keyData, "-----END PRIVATE KEY-----") ||
		strings.Contains(keyData, "-----END RSA PRIVATE KEY-----") ||
		strings.Contains(keyData, "-----END EC PRIVATE KEY-----")

	if !hasValidFooter {
		klog.Errorf("Private key missing valid END footer")
		return false
	}

	return true
}

func (c *CertificateController) validateSecret(secret *corev1.Secret) error {
	if secret.Type != corev1.SecretTypeTLS {
		return fmt.Errorf("secret is not of type TLS (got: %s)", secret.Type)
	}

	if len(secret.Data[corev1.TLSCertKey]) == 0 {
		return fmt.Errorf("secret does not contain certificate data")
	}

	if len(secret.Data[corev1.TLSPrivateKeyKey]) == 0 {
		return fmt.Errorf("secret does not contain private key data")
	}

	return nil
}

func (c *CertificateController) getCertificateSNIs(cert *certmanagerv1.Certificate) []string {
	var snis []string

	if cert.Spec.CommonName != "" {
		cleanCN := strings.Trim(cert.Spec.CommonName, "'\"")
		snis = append(snis, cleanCN)
	}

	for _, dnsName := range cert.Spec.DNSNames {
		cleanDNS := strings.Trim(dnsName, "'\"")
		snis = append(snis, cleanDNS)
	}

	return uniqueStrings(snis)
}

func uniqueStrings(slice []string) []string {
	if len(slice) == 0 {
		return slice
	}

	seen := make(map[string]bool)
	result := []string{}

	for _, str := range slice {
		if str == "" {
			continue
		}
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}

	return result
}

func (c *CertificateController) generateTags(namespace, name string, cert *certmanagerv1.Certificate) []string {
	tags := []string{
		"managed-by-kong-cert-sync",
		fmt.Sprintf("namespace:%s", namespace),
		fmt.Sprintf("certificate:%s", name),
		fmt.Sprintf("synced-at:%d", time.Now().Unix()),
	}

	if clusterName := c.config.Controller.ClusterName; clusterName != "" {
		tags = append(tags, fmt.Sprintf("cluster:%s", clusterName))
	}

	for key, value := range cert.Labels {
		tags = append(tags, fmt.Sprintf("%s:%s", key, value))
	}

	return tags
}

func (c *CertificateController) deleteCertificateFromKong(namespace, certName string) error {
	cert, err := c.certManagerClient.CertmanagerV1().Certificates(namespace).Get(
		context.Background(),
		certName,
		metav1.GetOptions{},
	)
	if err != nil {
		klog.Warningf("Certificate %s/%s not found, cannot delete from Kong", namespace, certName)
		return nil
	}

	snis := c.getCertificateSNIs(cert)
	if len(snis) == 0 {
		klog.Warningf("Certificate %s/%s has no SNIs, cannot delete from Kong", namespace, certName)
		return nil
	}

	klog.Infof("Deleting certificate %s/%s from Kong (SNIs: %v)", namespace, certName, snis)
	return c.kongClient.DeleteCertificateBySNIs(snis)
}

func (c *CertificateController) shouldSync(cert *certmanagerv1.Certificate) bool {
	if !c.matchesLabelSelector(cert) {
		klog.V(3).Infof("Certificate %s/%s does not match label selector", cert.Namespace, cert.Name)
		return false
	}

	if !c.isCertificateReady(cert) {
		klog.V(2).Infof("Certificate %s/%s is not ready yet", cert.Namespace, cert.Name)
		return false
	}

	if cert.Status.NotAfter.IsZero() {
		klog.V(2).Infof("Certificate %s/%s has no expiration time", cert.Namespace, cert.Name)
		return false
	}

	if time.Now().After(cert.Status.NotAfter.Time) {
		klog.V(2).Infof("Certificate %s/%s has expired", cert.Namespace, cert.Name)
		return false
	}

	klog.V(3).Infof("Certificate %s/%s should be synced", cert.Namespace, cert.Name)
	return true
}

func (c *CertificateController) isCertificateReady(cert *certmanagerv1.Certificate) bool {
	if cert == nil || cert.Status.Conditions == nil {
		return false
	}

	for _, condition := range cert.Status.Conditions {
		if condition.Type == certmanagerv1.CertificateConditionReady {
			return condition.Status == cmmeta.ConditionTrue
		}
	}
	return false
}

func (c *CertificateController) matchesLabelSelector(cert *certmanagerv1.Certificate) bool {
	if c.config.Controller.LabelSelector == "" {
		return true
	}

	selector, err := labels.Parse(c.config.Controller.LabelSelector)
	if err != nil {
		klog.Errorf("Failed to parse label selector: %v", err)
		return false
	}

	return selector.Matches(labels.Set(cert.Labels))
}

func (c *CertificateController) findCertificateBySecretName(namespace, secretName string) *certmanagerv1.Certificate {
	certificates, err := c.certificateInformer.GetIndexer().ByIndex(cache.NamespaceIndex, namespace)
	if err != nil {
		klog.Errorf("Failed to get certificates from cache: %v", err)
		return nil
	}

	for _, obj := range certificates {
		cert := obj.(*certmanagerv1.Certificate)
		if cert.Spec.SecretName == secretName {
			return cert
		}
	}

	return nil
}

func (c *CertificateController) certificateChanged(oldCert, newCert *certmanagerv1.Certificate) bool {
	if oldCert.ResourceVersion == newCert.ResourceVersion {
		return false
	}

	if oldCert.Spec.SecretName != newCert.Spec.SecretName {
		return true
	}

	if len(oldCert.Spec.DNSNames) != len(newCert.Spec.DNSNames) {
		return true
	}

	oldReady := c.isCertificateReady(oldCert)
	newReady := c.isCertificateReady(newCert)

	if oldReady != newReady {
		return true
	}

	for i, dnsName := range oldCert.Spec.DNSNames {
		if dnsName != newCert.Spec.DNSNames[i] {
			return true
		}
	}

	return false
}

// internal/controller/certificate_controller.go (续)

func (c *CertificateController) secretDataChanged(oldSecret, newSecret *corev1.Secret) bool {
	if oldSecret.ResourceVersion == newSecret.ResourceVersion {
		return false
	}

	oldCertData := oldSecret.Data[corev1.TLSCertKey]
	newCertData := newSecret.Data[corev1.TLSCertKey]
	oldKeyData := oldSecret.Data[corev1.TLSPrivateKeyKey]
	newKeyData := newSecret.Data[corev1.TLSPrivateKeyKey]

	if !bytes.Equal(oldCertData, newCertData) || !bytes.Equal(oldKeyData, newKeyData) {
		return true
	}

	return false
}

func (c *CertificateController) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *CertificateController) processNextWorkItem() bool {
	obj, quit := c.syncQueue.Get()
	if quit {
		return false
	}
	defer c.syncQueue.Done(obj)

	err := c.syncHandler(obj.(string))
	if err != nil {
		c.syncQueue.AddRateLimited(obj)
		klog.Errorf("Error syncing %s: %v", obj, err)
		return true
	}

	c.syncQueue.Forget(obj)
	return true
}

func (c *CertificateController) getQueueKey(namespace, name, eventType string) string {
	return fmt.Sprintf("%s/%s/%s", namespace, name, eventType)
}

func (c *CertificateController) parseQueueKey(key string) (namespace, name, eventType string, err error) {
	parts := strings.Split(key, "/")
	if len(parts) != 3 {
		err = fmt.Errorf("invalid queue key format: %s", key)
		return
	}
	return parts[0], parts[1], parts[2], nil
}

func (c *CertificateController) monitorKongCertificates(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count, err := c.kongClient.GetCertificateCount()
			if err != nil {
				klog.Errorf("Failed to get Kong certificate count: %v", err)
				continue
			}
			klog.V(2).Infof("Current Kong certificate count: %d", count)
		}
	}
}
