package generator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func fetchText(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request for %s: %w", url, err)
	}

	req.Header.Set("User-Agent", "oss-attributions-generator")

	client := &http.Client{Timeout: 20 * time.Second}

	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch %s: %w", url, err)
	}

	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, res.Body)

		return "", fmt.Errorf("http %d for %s", res.StatusCode, url)
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body from %s: %w", url, err)
	}

	return string(b), nil
}

// loadSpdxNameMap maps SPDX ID to human-readable name. Exceptions are included
// because the right-hand side of a "WITH" gets its own attribution block.
func loadSpdxNameMap(ctx context.Context, spdxVersion string) (map[string]string, error) {
	names, err := fetchSpdxNames(ctx, fmt.Sprintf(spdxNameMapURLFmt, spdxVersion))
	if err != nil {
		return nil, err
	}

	exceptions, err := fetchSpdxNames(ctx, fmt.Sprintf(spdxExceptionMapURLFmt, spdxVersion))
	if err != nil {
		return nil, err
	}

	maps.Copy(names, exceptions)

	return names, nil
}

// fetchSpdxNames reads one SPDX license-list-data name file. licenses.json and
// exceptions.json share a shape apart from the array and ID field names, so both
// are decoded by the same payload.
func fetchSpdxNames(ctx context.Context, url string) (map[string]string, error) {
	body, err := fetchText(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch SPDX name map from %s: %w", url, err)
	}

	var payload struct {
		Licenses []struct {
			ID   string `json:"licenseId"`
			Name string `json:"name"`
		} `json:"licenses"`
		Exceptions []struct {
			ID   string `json:"licenseExceptionId"`
			Name string `json:"name"`
		} `json:"exceptions"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SPDX name map from %s: %w", url, err)
	}

	out := make(map[string]string, len(payload.Licenses)+len(payload.Exceptions))

	for _, l := range payload.Licenses {
		out[l.ID] = l.Name
	}

	for _, e := range payload.Exceptions {
		out[e.ID] = e.Name
	}

	return out, nil
}

// spdxIDPattern matches the character set SPDX allows in a license or exception
// ID. It doubles as a path-segment guard, since IDs come verbatim from the SBOM.
var spdxIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]*$`)

// licenseRefPattern guards the "LicenseRef-" branch. It allows "_", which the
// SPDX idstring grammar forbids, because trivy derives these IDs from filenames.
var licenseRefPattern = regexp.MustCompile(`^(?:DocumentRef-[A-Za-z0-9._-]+:)?LicenseRef-[A-Za-z0-9._-]+$`)

func isLicenseRef(licenseID string) bool {
	return strings.HasPrefix(licenseID, "LicenseRef-") || strings.HasPrefix(licenseID, "DocumentRef-")
}

func getLicenseText(ctx context.Context, cfg Config, licenseID string) (string, error) {
	if ref := isLicenseRef(licenseID); (ref && !licenseRefPattern.MatchString(licenseID)) ||
		(!ref && !spdxIDPattern.MatchString(licenseID)) {
		return "", fmt.Errorf("invalid license identifier %q", licenseID)
	}

	cachePath := filepath.Join(cfg.OutLicensesDir, licenseID+".txt")

	if b, err := os.ReadFile(cachePath); err == nil {
		return string(b), nil
	}

	if isLicenseRef(licenseID) {
		customPath := filepath.Join(cfg.OutLicensesDir, "custom", licenseID+".txt")

		b, err := os.ReadFile(customPath)
		if err != nil {
			return "", fmt.Errorf("unknown license %q: expected custom license text at %s: %w", licenseID, customPath, err)
		}

		return string(b), nil
	}

	url := fmt.Sprintf(spdxLicenseTextURLFmt, cfg.SPDXVersion, licenseID)

	txt, err := fetchText(ctx, url)
	if err != nil {
		return "", fmt.Errorf("could not fetch SPDX text for %s from %s: %w", licenseID, url, err)
	}

	if err := writeText(cachePath, txt); err != nil {
		return "", fmt.Errorf("failed to cache SPDX text for %s at %s: %w", licenseID, cachePath, err)
	}

	return txt, nil
}
