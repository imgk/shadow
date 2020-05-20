package windivert

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"net/http"
	"strconv"
	"strings"
)

func Download() error {
	var (
		ver = "2.2.0"
		url = "https://github.com/basil00/Divert/releases/download/v" + ver + "/WinDivert-" + ver + "-A.zip"
		sys = "WinDivert" + strconv.Itoa(32 << (^uint(0)>>63)) + ".sys"
	)

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

			break
		}
	}

	return nil
}
