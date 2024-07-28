package anchors

import (
	"encoding/xml"
	"github.com/miekg/dns"
	"io"
	"os"
	"time"
)

// GetAllFromFile returns all DS records from the file path.
func GetAllFromFile(path string) ([]*dns.DS, error) {
	xmlFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer xmlFile.Close()
	return GetAllFromReader(xmlFile)
}

// GetValidFromFile returns only currently valid DS records from the file path..
func GetValidFromFile(path string) ([]*dns.DS, error) {
	xmlFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer xmlFile.Close()
	return GetValidFromReader(xmlFile)
}

// GetAllFromEmbedded returns all DS records from the embedded copy of the XML.
func GetAllFromEmbedded() []*dns.DS {
	records, err := GetAllFromReader(EmbeddedAnchors())
	if err != nil {
		panic(err)
	}
	return records
}

// GetValidFromEmbedded returns only currently valid DS records from the embedded copy of the XML.
func GetValidFromEmbedded() []*dns.DS {
	records, err := GetValidFromReader(EmbeddedAnchors())
	if err != nil {
		panic(err)
	}
	return records
}

// GetAllFromReader returns all DS records from the Reader.
func GetAllFromReader(r io.Reader) ([]*dns.DS, error) {
	return get(r, false)
}

// GetValidFromReader returns only currently valid DS records from the Reader.
func GetValidFromReader(r io.Reader) ([]*dns.DS, error) {
	return get(r, true)
}

//---

// TrustAnchor represents the root XML element.
type TrustAnchor struct {
	XMLName    xml.Name    `xml:"TrustAnchor"`
	ID         string      `xml:"id,attr"`
	Source     string      `xml:"source,attr"`
	Zone       string      `xml:"Zone"`
	KeyDigests []KeyDigest `xml:"KeyDigest"`
}

// KeyDigest represents the KeyDigest elements within the TrustAnchor.
type KeyDigest struct {
	ID         string    `xml:"id,attr"`
	ValidFrom  time.Time `xml:"validFrom,attr"`
	ValidUntil time.Time `xml:"validUntil,attr,omitempty"`
	KeyTag     uint16    `xml:"KeyTag"`
	Algorithm  uint8     `xml:"Algorithm"`
	DigestType uint8     `xml:"DigestType"`
	Digest     string    `xml:"Digest"`
}

// get parses the XML data and returns DS records.
// If validNow is true, it filters the records to include only those that are currently valid.
func get(r io.Reader, validNow bool) ([]*dns.DS, error) {
	byteValue, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var trustAnchor TrustAnchor
	err = xml.Unmarshal(byteValue, &trustAnchor)
	if err != nil {
		return nil, err
	}

	answers := make([]*dns.DS, 0)
	for _, kd := range trustAnchor.KeyDigests {
		if validNow {
			now := time.Now()

			// If time t is before this record is valid
			if now.Before(kd.ValidFrom) {
				continue
			}

			// If we have validUntil time, and time t is after it
			if !kd.ValidUntil.IsZero() && now.After(kd.ValidUntil) {
				continue
			}
		}

		answer := new(dns.DS)

		answer.Hdr = dns.RR_Header{
			Name:   trustAnchor.Zone,
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    0,
		}

		answer.KeyTag = kd.KeyTag
		answer.Algorithm = kd.Algorithm
		answer.DigestType = kd.DigestType
		answer.Digest = kd.Digest

		answers = append(answers, answer)
	}

	return answers, nil
}
