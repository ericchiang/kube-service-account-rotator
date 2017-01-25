package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/ericchiang/k8s"
	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"
	jose "gopkg.in/square/go-jose.v2"
)

const version = "v0.1.0"

func main() {
	cmd().Execute()
}

type config struct {
	kubeconfigPath    string
	rootCAPath        string
	signingKeyPath    string
	rotationFrequency time.Duration
	namespace         string
}

func cmd() *cobra.Command {
	c := new(config)

	root := &cobra.Command{
		Use:   "kube-cred-rotator",
		Short: "A tool for rotating service account credentials.",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("enter a subcommand")
		},
	}

	f := root.PersistentFlags()
	f.StringVar(&c.kubeconfigPath, "kubeconfig", "", "Path to a kubeconfig file to use to talk to the API.")
	f.StringVar(&c.rootCAPath, "root-ca", "", "Path to the API server's root CA.")
	f.StringVar(&c.signingKeyPath, "signing-key", "", "Path to the private key used to sign service account JWTs.")
	f.DurationVar(&c.rotationFrequency, "rotation-frequency", time.Hour*12, "How often to rotate service account credentials.")
	f.StringVar(&c.namespace, "namespace", "", "Namespace to rotate credentials in. Defaults to value from kubeconfig.")

	// Convert a function that takes a controller and convert it to
	// a cobra command method.
	run := func(f func(*controller) error) func(cmd *cobra.Command, args []string) {
		return func(cmd *cobra.Command, args []string) {
			err := func() error {
				if len(args) != 0 {
					return errors.New("surplus arguments")
				}
				controller, err := c.newController()
				if err != nil {
					return err
				}
				return f(controller)
			}()
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(2)
			}
		}
	}

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version and exit.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	})

	root.AddCommand(&cobra.Command{
		Use:   "run",
		Short: "Loop as a controller and continuously rotate credentials.",
		Run: run(func(c *controller) error {
			c.run(context.Background())
			return nil
		}),
	})

	root.AddCommand(&cobra.Command{
		Use:   "rotate",
		Short: "Rotate any expired service account credentials and exit.",
		Run: run(func(c *controller) error {
			return c.rotate(context.Background())
		}),
	})

	root.AddCommand(&cobra.Command{
		Use:   "mark",
		Short: "Mark pods for deletion and exit.",
		Run: run(func(c *controller) error {
			return c.markPods(context.Background())
		}),
	})

	root.AddCommand(&cobra.Command{
		Use:   "delete",
		Short: "Delete pods that need to be load new credentials and exit.",
		Run: run(func(c *controller) error {
			return c.deletePods(context.Background())
		}),
	})
	return root
}

func (c *config) newController() (*controller, error) {
	var k8sClient *k8s.Client
	if len(c.kubeconfigPath) == 0 {
		client, err := k8s.NewInClusterClient()
		if err != nil {
			return nil, fmt.Errorf("creating in cluster client: %v", err)
		}
		k8sClient = client
	} else {
		client, err := loadKubeconfig(c.kubeconfigPath)
		if err != nil {
			return nil, err
		}
		k8sClient = client
	}

	ns := c.namespace
	if len(ns) == 0 {
		ns = k8sClient.Namespace
	}
	if len(ns) == 0 {
		return nil, errors.New("no default namespace provided for kubernetes client")
	}

	// TODO: verify this is a certificate.
	data, err := ioutil.ReadFile(c.rootCAPath)
	if err != nil {
		return nil, fmt.Errorf("read root ca: %v", err)
	}

	signer, err := loadSigner(c.signingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load signing key: %v", err)
	}
	return &controller{
		client:    k8sClient.CoreV1(),
		namespace: ns,
		rootCA:    data,
		signer:    signer,
		now:       time.Now,
		logger: &logrus.Logger{
			Out: os.Stderr,
			Formatter: &logrus.TextFormatter{
				DisableColors: true,
			},
			Level: logrus.DebugLevel,
		},
		rotateAfter: c.rotationFrequency,
	}, nil
}

func loadKubeconfig(kubeconfigPath string) (*k8s.Client, error) {
	data, err := ioutil.ReadFile(kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("read kubeconfig: %v", err)
	}

	var config k8s.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("unmarshal kubeconfig: %v", err)
	}
	return k8s.NewClient(&config)
}

func loadSigner(filepath string) (jose.Signer, error) {
	priv, err := loadPrivateKey(filepath)
	if err != nil {
		return nil, err
	}
	alg, err := func() (jose.SignatureAlgorithm, error) {
		switch key := priv.(type) {
		case *rsa.PrivateKey:
			// TODO: Choose a different algorithm based on the length.
			return jose.RS256, nil
		case *ecdsa.PrivateKey:
			switch key.Params() {
			case elliptic.P256().Params():
				return jose.ES256, nil
			case elliptic.P384().Params():
				return jose.ES384, nil
			case elliptic.P521().Params():
				return jose.ES512, nil
			default:
				return jose.SignatureAlgorithm(""), errors.New("unsupported ecdsa curve")
			}
		}
		return jose.SignatureAlgorithm(""), fmt.Errorf("unsupported signing key type %T", priv)
	}()

	return jose.NewSigner(jose.SigningKey{
		Algorithm: alg,
		Key:       priv,
	}, &jose.SignerOptions{})
}

func loadPrivateKey(filepath string) (interface{}, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %v", err)
	}

	input := data
	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err0 := x509.ParsePKCS1PrivateKey(input)
	if err0 == nil {
		return priv, nil
	}

	priv, err1 := x509.ParsePKCS8PrivateKey(input)
	if err1 == nil {
		return priv, nil
	}

	priv, err2 := x509.ParseECPrivateKey(input)
	if err2 == nil {
		return priv, nil
	}

	return nil, fmt.Errorf("parse error, got '%s', '%s' and '%s'", err0, err1, err2)
}
