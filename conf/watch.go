package conf

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

func (p *Conf) Watch(filePath, xDnsPath string, sDnsPath string, reload func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("new watcher error: %s", err)
	}

	err = watcher.Add(filePath)
	if err != nil {
		watcher.Close()
		return fmt.Errorf("watch file error: %s", err)
	}
	if xDnsPath != "" {
		err = watcher.Add(xDnsPath)
		if err != nil {
			watcher.Close()
			return fmt.Errorf("watch dns file error: %s", err)
		}
	}
	if sDnsPath != "" {
		err = watcher.Add(sDnsPath)
		if err != nil {
			watcher.Close()
			return fmt.Errorf("watch dns file error: %s", err)
		}
	}

	var reloadMu sync.Mutex
	go func() {
		var pre time.Time
		defer watcher.Close()
		for {
			select {
			case e := <-watcher.Events:
				if e.Has(fsnotify.Chmod) {
					continue
				}
				if pre.Add(10 * time.Second).After(time.Now()) {
					continue
				}
				pre = time.Now()
				go func() {
					time.Sleep(5 * time.Second)
					reloadMu.Lock()
					defer reloadMu.Unlock()
					switch filepath.Base(strings.TrimSuffix(e.Name, "~")) {
					case filepath.Base(xDnsPath), filepath.Base(sDnsPath):
						log.Println("DNS file changed, reloading...")
					default:
						log.Println("config file changed, reloading...")
					}
					next := New()
					err := next.LoadFromPath(filePath)
					if err != nil {
						log.Printf("reload config error: %s", err)
						return
					}
					*p = *next
					reload()
					log.Println("reload config success")
				}()
			case err := <-watcher.Errors:
				if err != nil {
					log.Printf("File watcher error: %s", err)
				}
			}
		}
	}()
	return nil
}
