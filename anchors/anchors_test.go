package anchors

import (
	"bytes"
	"os"
	"testing"
)

func TestGetAll(t *testing.T) {
	xmlData := `
	<TrustAnchor id="1" source="example" Zone="example.com">
		<KeyDigest id="kd1" validFrom="2023-01-01T00:00:00Z" validUntil="2025-01-01T00:00:00Z">
			<KeyTag>12345</KeyTag>
			<Algorithm>8</Algorithm>
			<DigestType>2</DigestType>
			<Digest>ABCDEF</Digest>
		</KeyDigest>
		<KeyDigest id="kd2" validFrom="2023-01-01T00:00:00Z" validUntil="2025-01-01T00:00:00Z">
			<KeyTag>6789</KeyTag>
			<Algorithm>8</Algorithm>
			<DigestType>2</DigestType>
			<Digest>123456</Digest>
		</KeyDigest>
	</TrustAnchor>`

	r := bytes.NewReader([]byte(xmlData))
	dsRecords, err := GetAllFromReader(r)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(dsRecords) != 2 {
		t.Fatalf("expected 2 DS records, got %d", len(dsRecords))
	}

	// Validate first DS record
	ds1 := dsRecords[0]
	if ds1.KeyTag != 12345 || ds1.Algorithm != 8 || ds1.DigestType != 2 || ds1.Digest != "ABCDEF" {
		t.Fatalf("unexpected DS record: %+v", ds1)
	}

	// Validate second DS record
	ds2 := dsRecords[1]
	if ds2.KeyTag != 6789 || ds2.Algorithm != 8 || ds2.DigestType != 2 || ds2.Digest != "123456" {
		t.Fatalf("unexpected DS record: %+v", ds2)
	}
}

func TestGetValid(t *testing.T) {
	xmlData := `
	<TrustAnchor id="1" source="example" Zone="example.com">
		<KeyDigest id="kd1" validFrom="2023-01-01T00:00:00Z" validUntil="2025-01-01T00:00:00Z">
			<KeyTag>12345</KeyTag>
			<Algorithm>8</Algorithm>
			<DigestType>2</DigestType>
			<Digest>ABCDEF</Digest>
		</KeyDigest>
		<KeyDigest id="kd2" validFrom="2020-01-01T00:00:00Z" validUntil="2022-01-01T00:00:00Z">
			<KeyTag>54321</KeyTag>
			<Algorithm>8</Algorithm>
			<DigestType>2</DigestType>
			<Digest>FEDCBA</Digest>
		</KeyDigest>
	</TrustAnchor>`

	r := bytes.NewReader([]byte(xmlData))
	dsRecords, err := GetValidFromReader(r)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(dsRecords) != 1 {
		t.Fatalf("expected 1 DS record, got %d", len(dsRecords))
	}

	ds := dsRecords[0]
	if ds.KeyTag != 12345 || ds.Algorithm != 8 || ds.DigestType != 2 || ds.Digest != "ABCDEF" {
		t.Fatalf("unexpected DS record: %+v", ds)
	}
}

func TestGetAllInvalidXML(t *testing.T) {
	xmlData := `<TrustAnchor><Invalid></Invalid></TrustAnchor` // Missing closing >

	r := bytes.NewReader([]byte(xmlData))
	_, err := GetAllFromReader(r)
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestGetValidInvalidDates(t *testing.T) {
	xmlData := `
	<TrustAnchor id="1" source="example" Zone="example.com">
		<KeyDigest id="kd1" validFrom="invalid-date" validUntil="2025-01-01T00:00:00Z">
			<KeyTag>12345</KeyTag>
			<Algorithm>8</Algorithm>
			<DigestType>2</DigestType>
			<Digest>ABCDEF</Digest>
		</KeyDigest>
	</TrustAnchor>`

	r := bytes.NewReader([]byte(xmlData))
	_, err := GetValidFromReader(r)
	if err == nil {
		t.Fatalf("expected error, got none")
	}
}

func TestGetValidNoValidRecords(t *testing.T) {
	xmlData := `
	<TrustAnchor id="1" source="example" Zone="example.com">
		<KeyDigest id="kd1" validFrom="2020-01-01T00:00:00Z" validUntil="2022-01-01T00:00:00Z">
			<KeyTag>12345</KeyTag>
			<Algorithm>8</Algorithm>
			<DigestType>2</DigestType>
			<Digest>ABCDEF</Digest>
		</KeyDigest>
	</TrustAnchor>`

	r := bytes.NewReader([]byte(xmlData))
	dsRecords, err := GetValidFromReader(r)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(dsRecords) != 0 {
		t.Fatalf("expected 0 DS records, got %d", len(dsRecords))
	}
}

// New Tests for GetAllFromEmbedded and GetValidFromEmbedded
func TestGetAllFromEmbedded(t *testing.T) {
	dsRecords := GetAllFromEmbedded()

	// Validate the number of DS records based on the embedded XML
	if len(dsRecords) != 2 {
		t.Fatalf("expected 2 DS records, got %d", len(dsRecords))
	}
}

func TestGetValidFromEmbedded(t *testing.T) {
	dsRecords := GetValidFromEmbedded()

	// Validate the number of currently valid DS records based on the embedded XML
	if len(dsRecords) != 1 {
		t.Fatalf("expected 1 DS record, got %d", len(dsRecords))
	}
}

// Helper function to create a temporary file with the given content
func createTempFile(t *testing.T, content string) string {
	tmpFile, err := os.CreateTemp("", "root-anchors-*.xml")
	if err != nil {
		t.Fatalf("could not create temp file: %v", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write([]byte(content)); err != nil {
		t.Fatalf("could not write to temp file: %v", err)
	}

	return tmpFile.Name()
}

// New Tests for GetAllFromFile and GetValidFromFile
func TestGetAllFromFile(t *testing.T) {
	xmlData := `
	<TrustAnchor id="1" source="example" Zone="example.com">
		<KeyDigest id="kd1" validFrom="2023-01-01T00:00:00Z" validUntil="2025-01-01T00:00:00Z">
			<KeyTag>12345</KeyTag>
			<Algorithm>8</Algorithm>
			<DigestType>2</DigestType>
			<Digest>ABCDEF</Digest>
		</KeyDigest>
		<KeyDigest id="kd2" validFrom="2023-01-01T00:00:00Z" validUntil="2025-01-01T00:00:00Z">
			<KeyTag>6789</KeyTag>
			<Algorithm>8</Algorithm>
			<DigestType>2</DigestType>
			<Digest>123456</Digest>
		</KeyDigest>
	</TrustAnchor>`

	tmpFilePath := createTempFile(t, xmlData)
	defer os.Remove(tmpFilePath)

	dsRecords, err := GetAllFromFile(tmpFilePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(dsRecords) != 2 {
		t.Fatalf("expected 2 DS records, got %d", len(dsRecords))
	}
}

func TestGetValidFromFile(t *testing.T) {
	xmlData := `
	<TrustAnchor id="1" source="example" Zone="example.com">
		<KeyDigest id="kd1" validFrom="2023-01-01T00:00:00Z" validUntil="2025-01-01T00:00:00Z">
			<KeyTag>12345</KeyTag>
			<Algorithm>8</Algorithm>
			<DigestType>2</DigestType>
			<Digest>ABCDEF</Digest>
		</KeyDigest>
		<KeyDigest id="kd2" validFrom="2020-01-01T00:00:00Z" validUntil="2022-01-01T00:00:00Z">
			<KeyTag>54321</KeyTag>
			<Algorithm>8</Algorithm>
			<DigestType>2</DigestType>
			<Digest>FEDCBA</Digest>
		</KeyDigest>
	</TrustAnchor>`

	tmpFilePath := createTempFile(t, xmlData)
	defer os.Remove(tmpFilePath)

	dsRecords, err := GetValidFromFile(tmpFilePath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(dsRecords) != 1 {
		t.Fatalf("expected 1 DS record, got %d", len(dsRecords))
	}
}
