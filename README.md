# dns-anchors-go

The `dns-anchors-go` library is designed to convert the `root-anchors.xml` file, available from [IANA DNSSEC files](https://www.iana.org/dnssec/files), into `miekg/dns` DS records. This conversion supports DNSSEC chain validation, ensuring the integrity and authenticity of DNS data.

An example copy of `root-anchors.xml` is included in this repository. However, for security and reliability, it is recommended to acquire and validate this file independently to ensure trust in its content. Use the included copy at your own risk.

## Usage

To use `dns-anchors-go` in your Go project, follow the example below:
```go
package main

import (
	"os"
	"github.com/nsmithuk/dns-anchors-go/anchors"
	"fmt"
)

func main() {
	// Open the root-anchors.xml file
	xmlFile, err := os.Open("root-anchors.xml")
	if err != nil {
		panic(err)
	}
	defer xmlFile.Close()

	// Get valid (not expired) DS records
	dsRecords, err := anchors.GetValid(xmlFile)
	if err != nil {
		panic(err)
	}

	// Print the DS records
	for _, record := range dsRecords {
		fmt.Println(record)
	}
}
```

## Run the Tests

To run the tests for this project, use the following command:
```shell
go test ./...
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
