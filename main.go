package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"github.com/spf13/cobra"
	corev1types "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"
	aggv1beta1types "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
	aggv1beta1 "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1beta1"
)

type options struct {
	kubeconfig       string
	namespace        string
	secretName       string
	serviceName      string
	apiGroupName     string
	apiGroupVersions []string
	uninstall        bool
}

func (o *options) validate() error {
	if o.namespace == "" {
		return errors.New("no namespace specified")
	}
	if o.secretName == "" {
		return errors.New("no secret specified")
	}
	if o.serviceName == "" {
		return errors.New("no service specified")
	}
	if o.apiGroupName == "" {
		return errors.New("no api group specified")
	}
	if len(o.apiGroupVersions) == 0 {
		return errors.New("no api group version specified")
	}
	return nil
}

func (o *options) complete() (*operation, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", o.kubeconfig)
	if err != nil {
		return nil, err
	}
	coreclient, err := corev1.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	aggclient, err := aggv1beta1.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &operation{
		coreclient:       coreclient,
		aggclient:        aggclient,
		namespace:        o.namespace,
		secretName:       o.secretName,
		serviceName:      o.serviceName,
		apiGroupName:     o.apiGroupName,
		apiGroupVersions: o.apiGroupVersions,
		uninstall:        o.uninstall,
	}, nil
}

type operation struct {
	coreclient       corev1.CoreV1Interface
	aggclient        aggv1beta1.ApiregistrationV1beta1Interface
	namespace        string
	secretName       string
	serviceName      string
	apiGroupName     string
	apiGroupVersions []string
	uninstall        bool
}

func main() {
	opts := &options{}
	cmd := &cobra.Command{
		Use: "helm-api-registrator",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.validate(); err != nil {
				return err
			}
			op, err := opts.complete()
			if err != nil {
				return err
			}

			if op.uninstall {
				// delete and ignore errors
				op.coreclient.Secrets(op.namespace).Delete(op.secretName, nil)
				for _, v := range op.apiGroupVersions {
					op.aggclient.APIServices().Delete(fmt.Sprintf("%s.%s", v, op.apiGroupName), nil)
				}
				return nil
			}

			caKey, err := certutil.NewPrivateKey()
			if err != nil {
				return err
			}
			caCert, err := certutil.NewSelfSignedCACert(certutil.Config{
				CommonName: "generated-ca",
			}, caKey)
			if err != nil {
				return err
			}
			caBundle := certutil.EncodeCertPEM(caCert)

			key, err := certutil.NewPrivateKey()
			if err != nil {
				return err
			}
			cfg := certutil.Config{
				CommonName: fmt.Sprintf("%s.%s.svc", op.serviceName, op.namespace),
				AltNames: certutil.AltNames{
					DNSNames: []string{"localhost", fmt.Sprintf("%s.%s.svc", op.serviceName, op.namespace)},
					IPs:      []net.IP{loopbackIP},
				},
				Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			cert, err := certutil.NewSignedCert(cfg, key, caCert, caKey)

			if err != nil {
				return err
			}

			keyPEM := certutil.EncodePrivateKeyPEM(key)
			certPEM := certutil.EncodeCertPEM(cert)

			secret := &corev1types.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: op.secretName,
				},
				Data: map[string][]byte{
					"ca":   caBundle,
					"key":  keyPEM,
					"cert": certPEM,
				},
			}

			if _, err := op.coreclient.Secrets(op.namespace).Create(secret); err != nil {
				return err
			}

			for _, v := range op.apiGroupVersions {
				apiService := &aggv1beta1types.APIService{
					ObjectMeta: metav1.ObjectMeta{
						Name: fmt.Sprintf("%s.%s", v, op.apiGroupName),
					},
					Spec: aggv1beta1types.APIServiceSpec{
						InsecureSkipTLSVerify: false,
						CABundle:              caBundle,
						Group:                 op.apiGroupName,
						GroupPriorityMinimum:  1000,
						VersionPriority:       15,
						Version:               v,
						Service: &aggv1beta1types.ServiceReference{
							Namespace: op.namespace,
							Name:      op.serviceName,
						},
					},
				}
				if _, err := op.aggclient.APIServices().Create(apiService); err != nil {
					return err
				}
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.kubeconfig, "KUBECONFIG", "", "kubeconfig file (if not specified, use ambient config)")
	flags.StringVarP(&opts.namespace, "namespace", "n", "default", "namespace of service and secret")
	flags.StringVar(&opts.secretName, "secret", "", "name of the generated secret")
	flags.StringVar(&opts.serviceName, "service", "", "name of the service exposing the API")
	flags.StringVarP(&opts.apiGroupName, "apigroup", "g", "", "api group to register")
	flags.StringSliceVarP(&opts.apiGroupVersions, "version", "v", nil, "versions to register (one per version)")
	flags.BoolVarP(&opts.uninstall, "uninstall", "u", false, "uninstall")

	if err := cmd.Execute(); err != nil {
		panic(err)
	}
}

var loopbackIP = net.ParseIP("127.0.0.1")
