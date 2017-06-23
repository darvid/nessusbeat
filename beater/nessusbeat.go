package beater

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/publisher"

	"github.com/attwad/nessie"
	"github.com/fsnotify/fsnotify"

	"github.com/darvid/nessusbeat/config"
)

func GetScanIDByUUID(nessus nessie.Nessus, uuid string) (int64, error) {
	result, err := nessus.Scans()
	if err != nil {
		return -1, err
	}
	for _, scan := range result.Scans {
		if scan.UUID == uuid {
			return scan.ID, nil
		}
	}
	return -1, nil
}

type Nessusbeat struct {
	done   chan struct{}
	config config.Config
	client publisher.Client
}

func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	config := config.DefaultConfig
	if err := cfg.Unpack(&config); err != nil {
		return nil, fmt.Errorf("Error reading config file: %v", err)
	}

	bt := &Nessusbeat{
		done:   make(chan struct{}),
		config: config,
	}
	return bt, nil
}

func (bt *Nessusbeat) Run(b *beat.Beat) error {
	logp.Info("nessusbeat is running! Hit CTRL-C to stop it.")

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logp.WTF(err.Error())
	}
	defer watcher.Close()
	err = watcher.Add(bt.config.ReportPath)
	if err != nil {
		logp.WTF(err.Error())
	}

	bt.client = b.Publisher.Connect()
	results := make(chan []byte)

	var nessus nessie.Nessus
	if bt.config.CaCertPath != "" {
		nessus, err = nessie.NewNessus(bt.config.NessusApiUrl, bt.config.CaCertPath)
	} else {
		nessus, err = nessie.NewInsecureNessus(bt.config.NessusApiUrl)
	}
	if err != nil {
		logp.WTF(err.Error())
	}

	if err := nessus.Login(bt.config.NessusApiUsername, bt.config.NessusApiPassword); err != nil {
		logp.WTF(err.Error())
	}
	defer nessus.Logout()

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				ext := filepath.Ext(event.Name)
				if event.Op&fsnotify.Write == fsnotify.Write && ext == ".nessus" {
					basename := filepath.Base(event.Name)
					logp.Info("Exporting scan %s", basename)
					uuid := strings.TrimSuffix(basename, filepath.Ext(basename))
					scanID, err := GetScanIDByUUID(nessus, uuid)
					if err != nil {
						logp.WTF(err.Error())
					}
					exportID, err := nessus.ExportScan(scanID, nessie.ExportCSV)
					if err != nil {
						logp.WTF(err.Error())
					}
					for {
						if finished, err := nessus.ExportFinished(scanID, exportID); err != nil {
							logp.WTF(err.Error())
						} else if finished {
							break
						}
						time.Sleep(5 * time.Second)
					}
					csv, err := nessus.DownloadExport(scanID, exportID)
					if err != nil {
						logp.WTF(err.Error())
					}
					results <- csv
				}
			case err := <-watcher.Errors:
				logp.Err(err.Error())
			}
		}
	}()

	for {
		select {
		case <-bt.done:
			return nil
		case result := <-results:
			r := csv.NewReader(bytes.NewReader(result))
			_, err := r.Read() // skip header row
			if err != nil {
				logp.WTF(err.Error())
			}
			for {
				record, err := r.Read()
				if err == io.EOF {
					break
				}
				if err != nil {
					logp.WTF(err.Error())
				}
				if len(record) != 13 {
					logp.Err("Invalid number of fields: %d", len(record))
					continue
				}
				event := common.MapStr{
					"@timestamp":    common.Time(time.Now()),
					"type":          b.Info.Name,
					"plugin_id":     record[0],
					"cve":           record[1],
					"cvss":          record[2],
					"risk":          record[3],
					"host":          record[4],
					"protocol":      record[5],
					"port":          record[6],
					"name":          record[7],
					"synopsis":      record[8],
					"description":   record[9],
					"solution":      record[10],
					"see_also":      record[11],
					"plugin_output": record[12],
				}
				bt.client.PublishEvent(event)
			}
		}
	}
}

func (bt *Nessusbeat) Stop() {
	bt.client.Close()
	close(bt.done)
}
