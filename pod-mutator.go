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
	corev1 "k8s.io/api/core/v1"
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
	fl.StringVar(&cfg.certFile, "tls-cert-file", "/etc/pod-mutator/tls/cert.pem", "TLS certificate file")
	fl.StringVar(&cfg.keyFile, "tls-key-file", "/etc/pod-mutator/tls/key.pem", "TLS key file")
	fl.StringVar(&cfg.rulesFile, "rules-file", "/etc/pod-mutator/rules/rules.json", "rules file")
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
						panic(err)
					}
					err = watcher.Add(cfg.rulesFile)
					if err != nil {
						panic(err)
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
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return &kwhmutating.MutatorResult{}, nil
		}
		var patchedPod corev1.Pod

		patched := false
		for _, rule := range rules.Rules {
			// Check if the namespace matches the rule
			namespacere, err := regexp.Compile(rule.NamespaceRe)
			if err != nil {
				return nil, fmt.Errorf("bad namespace regex: %v", err)
			}
			if !namespacere.MatchString(pod.Namespace) {
				continue
			}

			// Check if the name matches the rule
			namere, err := regexp.Compile(rule.NameRe)
			if err != nil {
				return nil, fmt.Errorf("bad name regex: %v", err)
			}
			if !namere.MatchString(pod.Name) {
				continue
			}

			// Marshal the pod to JSON
			podJson, err := json.Marshal(pod)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal pod: %v", err)
			}

			// Decode the JSON patch in the rule
			patch, err := jsonpatch.DecodePatch([]byte(rule.Patch))
			if err != nil {
				return nil, fmt.Errorf("failed to decode patch: %v", err)
			}

			// Apply the patch to the pod
			patchedJson, err := patch.Apply(podJson)
			if err != nil {
				return nil, fmt.Errorf("failed to apply patch: %v", err)
			}

			// Unmarshal the patched pod back into a struct
			if err := json.Unmarshal(patchedJson, &patchedPod); err != nil {
				return nil, fmt.Errorf("failed to unmarshal pod: %v", err)
			}
			patched = true
		}
		if !patched {
			return &kwhmutating.MutatorResult{}, nil
		}
		var metaObj metav1.Object = &patchedPod
		return &kwhmutating.MutatorResult{MutatedObject: metaObj}, nil
	})
	// Create webhook.
	mcfg := kwhmutating.WebhookConfig{
		ID:      "pod-mutator.metal-stack.dev",
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

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error running app: %s", err)
		os.Exit(1)
	}
}
