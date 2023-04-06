package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/fsnotify/fsnotify"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/sirupsen/logrus"
	kwhhttp "github.com/slok/kubewebhook/v2/pkg/http"
	"github.com/slok/kubewebhook/v2/pkg/log"
	kwhlogrus "github.com/slok/kubewebhook/v2/pkg/log/logrus"
	kwhmodel "github.com/slok/kubewebhook/v2/pkg/model"
	kwhmutating "github.com/slok/kubewebhook/v2/pkg/webhook/mutating"
)

type config struct {
	certFile            string
	keyFile             string
	rulesFile           string
	HealthCheckNodePort int
}

type Rule struct {
	NamespaceRe string `json:"namespace"`
	NameRe      string `json:"name"`
	Patch       string `json:"patch"`
}

type Rules struct {
	Rules []Rule `json:"rules"`
}

func initFlags() (*config, error) {
	cfg := &config{}

	fl := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fl.StringVar(&cfg.certFile, "tls-cert-file", "/etc/mutator/tls/cert.pem", "TLS certificate file")
	fl.StringVar(&cfg.keyFile, "tls-key-file", "/etc/mutator/tls/key.pem", "TLS key file")
	fl.StringVar(&cfg.rulesFile, "rules-file", "/etc/mutator/rules/rules.json", "rules file")
	fl.IntVar(&cfg.HealthCheckNodePort, "health-check-node-port", 31397, "Health check node port")

	err := fl.Parse(os.Args[1:])
	if err != nil {
		return nil,
			err
	}
	return cfg, nil
}

func run() error {
	logrusLogEntry := logrus.NewEntry(logrus.New())
	logrusLogEntry.Logger.SetLevel(logrus.DebugLevel)
	logger := kwhlogrus.NewLogrus(logrusLogEntry)

	cfg, err := initFlags()
	if err != nil {
		return err
	}

	rules := readRules(cfg, logger)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		panic(err)
	}
	defer watcher.Close()

	// Start watching the config file
	err = watcher.Add(cfg.rulesFile)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op == fsnotify.Remove {
					err = watcher.Remove(event.Name)
					if err != nil {
						logger.Errorf("failed to remove file from watcher: %w", err)
					}

					err = watcher.Add(cfg.rulesFile)
					if err != nil {
						logger.Errorf("failed to add file to watcher: %w", err)
					}

					rules = readRules(cfg, logger)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Println("error:", err)
			}
		}
	}()

	// Create mutator.
	mt := kwhmutating.MutatorFunc(func(_ context.Context, _ *kwhmodel.AdmissionReview, obj metav1.Object) (*kwhmutating.MutatorResult, error) {

		var metaObj metav1.Object
		switch orig := obj.(type) {
		case *appsv1.Deployment:
			metaObj, err = handleDeployment(orig, rules)
		case *appsv1.StatefulSet:
			metaObj, err = handleStatefulSet(orig, rules)
		}
		return &kwhmutating.MutatorResult{MutatedObject: metaObj}, err
	})

	// Create webhook.
	mcfg := kwhmutating.WebhookConfig{
		ID:      "mutator.metal-stack.dev",
		Mutator: mt,
		Logger:  logger,
	}
	wh, err := kwhmutating.NewWebhook(mcfg)
	if err != nil {
		return fmt.Errorf("error creating webhook: %w", err)
	}

	// Get HTTP handler from webhook.
	whHandler, err := kwhhttp.HandlerFor(kwhhttp.HandlerConfig{Webhook: wh, Logger: logger})
	if err != nil {
		return fmt.Errorf("error creating webhook handler: %w", err)
	}

	// Serve.
	logger.Infof("Listening on :8080")

	http.Handle("/", whHandler)

	server := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 1 * time.Minute,
	}

	err = server.ListenAndServeTLS(cfg.certFile, cfg.keyFile)
	if err != nil {
		return fmt.Errorf("error serving webhook: %w", err)
	}

	return nil
}

func applyRules(name string, namespace string, origJson []byte, rules Rules) ([]byte, bool, error) {
	for _, rule := range rules.Rules {

		namespacere, err := regexp.Compile(rule.NamespaceRe)
		if err != nil {
			return nil, false, fmt.Errorf("bad namespace regex: %w", err)
		}
		if !namespacere.MatchString(namespace) {
			continue
		}

		namere, err := regexp.Compile(rule.NameRe)
		if err != nil {
			return nil, false, fmt.Errorf("bad name regex: %w", err)
		}
		if !namere.MatchString(name) {
			continue
		}

		patch, err := jsonpatch.DecodePatch([]byte(rule.Patch))
		if err != nil {
			return nil, false, fmt.Errorf("failed to decode patch: %w", err)
		}

		patchedJson, err := patch.Apply(origJson)
		if err != nil {
			return nil, false, fmt.Errorf("failed to apply patch: %w", err)
		}

		return patchedJson, true, nil
	}
	return nil, false, nil
}

func readRules(cfg *config, logger log.Logger) Rules {
	var rules Rules

	_, err := os.Stat(cfg.rulesFile)
	if !os.IsNotExist(err) {
		// if the file exists, open it
		f, err := os.Open(cfg.rulesFile)
		if err != nil {
			logger.Errorf("error opening file %s: %w", cfg.rulesFile, err)
		}
		// read the file contents into a byte array
		j, _ := io.ReadAll(f)
		f.Close()
		if err != nil {
			logger.Errorf("error closing file %s: %w", cfg.rulesFile, err)
		}
		// unmarshal the json into the Rules struct
		if err := json.Unmarshal(j, &rules); err != nil {
			logger.Errorf("error unmarshling rules %w", err)
		}
	} else {
		logger.Infof("file %s does not exist", cfg.rulesFile)
	}

	rls, err := json.Marshal(rules)
	if err != nil {
		logger.Errorf("error marshling rules %w", err)
	}
	logger.Infof("new rules: %s\n", string(rls))

	return rules
}

func handleDeployment(orig *appsv1.Deployment, rules Rules) (metav1.Object, error) {

	var patchedObj appsv1.Deployment

	origJson, err := json.Marshal(orig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pod: %w", err)
	}

	patchedJson, ok, err := applyRules(orig.Name, orig.Namespace, origJson, rules)
	if err != nil {
		return nil, fmt.Errorf("failed to patch pod: %w", err)
	}
	if !ok {
		return nil, nil
	}
	if err := json.Unmarshal(patchedJson, &patchedObj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pod: %w", err)
	}
	var metaObj metav1.Object = &patchedObj
	return metaObj, nil
}

func handleStatefulSet(orig *appsv1.StatefulSet, rules Rules) (metav1.Object, error) {

	var patchedObj appsv1.StatefulSet

	// Marshal the pod to JSON
	origJson, err := json.Marshal(orig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pod: %w", err)
	}

	patchedJson, ok, err := applyRules(orig.Name, orig.Namespace, origJson, rules)
	if err != nil {
		return nil, fmt.Errorf("failed to patch pod: %w", err)
	}
	if !ok {
		return nil, nil
	}
	if err := json.Unmarshal(patchedJson, &patchedObj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pod: %w", err)
	}

	var metaObj metav1.Object = &patchedObj
	return metaObj, nil
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error running app: %s", err)
		os.Exit(1)
	}
}
