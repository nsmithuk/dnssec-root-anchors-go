# dns-anchors-go

The `dns-anchors-go` library is designed to convert the `root-anchors.xml` file, available from [IANA DNSSEC files](https://www.iana.org/dnssec/files), into `miekg/dns` DS records. The root DS records are required to perform full validation of the DNSSEC chain.

This repository includes two copies of the root anchors - one embedded in a Go constant, and another copy in `root-anchors.xml`. Feel free to use these for convenience, however if you're serious about performing your own validation it is recommended to acquire and validate the file independently to ensure trust in its content. Use the included copies at your own risk.


## Usage

### Using the Embedded Data
```go
package main

import (
	"github.com/nsmithuk/dns-anchors-go/anchors"
	"fmt"
)

func main() {
	// Get valid (not expired) DS records from the embedded XML
	dsRecords := anchors.GetValidFromEmbedded()

	// Print the DS records
	for _, record := range dsRecords {
		fmt.Println(record)
	}
}

```

### Using a File Path
```go
package main

import (
	"github.com/nsmithuk/dns-anchors-go/anchors"
	"fmt"
)

func main() {
	// Get valid (not expired) DS records from the specified file
	dsRecords, err := anchors.GetValidFromFile("root-anchors.xml")
	if err != nil {
		panic(err)
	}

	// Print the DS records
	for _, record := range dsRecords {
		fmt.Println(record)
	}
}
```

### Using io.Reader
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
	dsRecords, err := anchors.GetValidFromReader(xmlFile)
	if err != nil {
		panic(err)
	}

	// Print the DS records
	for _, record := range dsRecords {
		fmt.Println(record)
	}
}
```
If you want all records, not just valid ones, there is: `GetAllFromFile()`, `GetAllFromEmbedded()` and `GetAllFromReader()`.

## Run the Tests

To run the tests for this project, use the following command:
```shell
go test ./...
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
