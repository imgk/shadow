package windivert

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

func Download() error {
	var (
		ver = "2.2.0"
		url = "https://github.com/basil00/Divert/releases/download/v" + ver + "/WinDivert-" + ver + "-A.zip"
		sys = ""
		dll = ""
	)

	if ^uint(0)>>63 == 1 {
		sys = "x64/WinDivert64.sys"
		dll = "x64/WinDivert.dll"
	} else {
		sys = "x86/WinDivert32.sys"
		dll = "x86/WinDivert.dll"
	}

	if _, err := os.Stat(windivertsys); err == nil {
		return nil
	}

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status code is %v", resp.StatusCode)
	}

	zipFile, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	reader := bytes.NewReader(zipFile)

	zipReader, err := zip.NewReader(reader, int64(reader.Len()))
	if err != nil {
		return err
	}

	for _, file := range zipReader.File {
		if strings.HasSuffix(file.Name, sys) {
			f, err := file.Open()
			if err != nil {
				return err
			}
			defer f.Close()

			data, err := ioutil.ReadAll(f)
			if err != nil {
				return err
			}

			if err = ioutil.WriteFile(windivertsys, data, 0444); err != nil {
				return err
			}
		}

		if strings.HasSuffix(file.Name, dll) {
			f, err := file.Open()
			if err != nil {
				return err
			}
			defer f.Close()

			data, err := ioutil.ReadAll(f)
			if err != nil {
				return err
			}

			if err = ioutil.WriteFile(windivertdll, data, 0444); err != nil {
				return err
			}
		}
	}

	return nil
}
