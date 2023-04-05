package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"syscall"
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
	fl.StringVar(&cfg.certFile, "tls-cert-file", "/etc/general-mutator/tls/cert.pem", "TLS certificate file")
	fl.StringVar(&cfg.keyFile, "tls-key-file", "/etc/general-mutator/tls/key.pem", "TLS key file")
	fl.StringVar(&cfg.rulesFile, "rules-file", "/etc/general-mutator/rules/rules.json", "rules file")
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

	// // Initialize the inotify watcher
	// watcher, err := unix.InotifyInit()
	// if err != nil {
	//     panic(err)
	// }

	// // Add the file to the watcher's list of files to watch
	// wd, err := unix.InotifyAddWatch(watcher, cfg.rulesFile, unix.IN_MODIFY)
	// if err != nil {
	//     panic(err)
	// }

	// // Continuously wait for events
	// for {
	// 	var buf [unix.SizeofInotifyEvent * 10]byte
	// 	n, err := unix.Read(watcher, buf[:])
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	// Convert the byte slice to a slice of InotifyEvent structs
	// 	events := (*[1 << 20]unix.InotifyEvent)(unsafe.Pointer(&buf[0]))[:n/unix.SizeofInotifyEvent]

	// 	for _, event := range events {
	// 		if event.Wd == int32(wd) {
	// 			fmt.Println("File has been modified")
	// 			// Do something here when the file has been modified
	// 		}
	// 	}
	// }

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		panic(err)
	}
	defer watcher.Close()

	// Set up signal handling for graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

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

			namespacere := regexp.MustCompile(rule.NamespaceRe)
			if !namespacere.MatchString(pod.Namespace) {
				continue
			}

			namere := regexp.MustCompile(rule.NameRe)
			if !namere.MatchString(pod.Name) {
				continue
			}

			podJson, err := json.Marshal(pod)
			if err != nil {
				panic(err)
			}

			patch, err := jsonpatch.DecodePatch([]byte(rule.Patch))
			if err != nil {
				panic(err)
			}

			patchedJson, err := patch.Apply(podJson)
			if err != nil {
				panic(err)
			}

			logger.Infof("patched pod: %s\n", string(patchedJson))
			if err := json.Unmarshal(patchedJson, &patchedPod); err != nil {
				panic(err)
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
		ID:      "general-mutator.metal-stack.dev",
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
		f, err := os.Open(cfg.rulesFile)
		if err != nil {
			logger.Errorf("error opening file %s: %w", cfg.rulesFile, err)
		}
		j, _ := io.ReadAll(f)
		f.Close()
		if err != nil {
			logger.Errorf("error closing file %s: %w", cfg.rulesFile, err)
		}
		if err := json.Unmarshal(j, &rules); err != nil {
			logger.Errorf("error unmarshling rules %w", err)
		}
	} else {
		logger.Infof("file %s does not exist", cfg.rulesFile)
	}

	// debug
	rls, err := json.Marshal(rules)
	if err != nil {
		panic(err)
	}
	logger.Infof("rules: %s\n", string(rls))

	return rules
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error running app: %s", err)
		os.Exit(1)
	}
}
