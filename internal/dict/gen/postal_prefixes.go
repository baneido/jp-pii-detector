package main

import (
	"archive/zip"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	input := flag.String("input", "", "Japan Post UTF-8 KEN_ALL CSV or zip path")
	output := flag.String("output", "", "output path for postal_prefixes.txt")
	flag.Parse()

	if *input == "" || *output == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}

	if err := generatePostalPrefixes(*input, *output); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func generatePostalPrefixes(inputPath, outputPath string) error {
	prefixes := map[string]struct{}{}
	if strings.EqualFold(filepath.Ext(inputPath), ".zip") {
		if err := readZip(inputPath, prefixes); err != nil {
			return err
		}
	} else {
		if err := readCSVFile(inputPath, prefixes); err != nil {
			return err
		}
	}
	if len(prefixes) == 0 {
		return fmt.Errorf("no postal prefixes found in %s", inputPath)
	}

	sorted := make([]string, 0, len(prefixes))
	for prefix := range prefixes {
		sorted = append(sorted, prefix)
	}
	sort.Strings(sorted)

	var b strings.Builder
	for _, prefix := range sorted {
		b.WriteString(prefix)
		b.WriteByte('\n')
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(outputPath, []byte(b.String()), 0o644)
}

func readZip(path string, prefixes map[string]struct{}) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer zr.Close()

	foundCSV := false
	for _, file := range zr.File {
		if file.FileInfo().IsDir() || !strings.EqualFold(filepath.Ext(file.Name), ".csv") {
			continue
		}
		foundCSV = true
		rc, err := file.Open()
		if err != nil {
			return err
		}
		err = readCSV(file.Name, rc, prefixes)
		closeErr := rc.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if !foundCSV {
		return fmt.Errorf("zip has no csv entries: %s", path)
	}
	return nil
}

func readCSVFile(path string, prefixes map[string]struct{}) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return readCSV(path, f, prefixes)
}

func readCSV(name string, r io.Reader, prefixes map[string]struct{}) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true

	for {
		record, err := cr.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if len(record) < 3 {
			return fmt.Errorf("%s: record has %d columns, want at least 3", name, len(record))
		}

		postalCode := strings.TrimSpace(record[2])
		if !isSevenDigitPostalCode(postalCode) {
			return fmt.Errorf("%s: invalid postal code in column 3: %q", name, postalCode)
		}
		prefixes[postalCode[:3]] = struct{}{}
	}
}

func isSevenDigitPostalCode(s string) bool {
	if len(s) != 7 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
