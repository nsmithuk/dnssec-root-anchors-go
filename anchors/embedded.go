package anchors

import (
	"io"
	"strings"
)

const Anchor = `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="E9724F53-1851-4F86-85E5-F1392102940B" source="http://data.iana.org/root-anchors/root-anchors.xml">
    <Zone>.</Zone>
    <KeyDigest id="Kjqmt7v" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
        <KeyTag>19036</KeyTag>
        <Algorithm>8</Algorithm>
        <DigestType>2</DigestType>
        <Digest>49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5</Digest>
    </KeyDigest>
    <KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00">
        <KeyTag>20326</KeyTag>
        <Algorithm>8</Algorithm>
        <DigestType>2</DigestType>
        <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
    </KeyDigest>
    <KeyDigest id="Kmyv6jo" validFrom="2024-07-18T00:00:00+00:00">
        <KeyTag>38696</KeyTag>
        <Algorithm>8</Algorithm>
        <DigestType>2</DigestType>
        <Digest>683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16</Digest>
    </KeyDigest>
</TrustAnchor>
`

func embeddedReader() io.Reader {
	return strings.NewReader(Anchor)
}
