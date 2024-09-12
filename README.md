# DNSSEC Trust Anchor Reader

Reads the DNSSEC trust anchors from `root-anchors.xml`, available from [IANA DNSSEC files](https://www.iana.org/dnssec/files), into `miekg/dns` DS records.

> [!CAUTION]
> This repository includes an embedded copy of the root anchors as a constant. Feel free to use it for convenience, 
> however if you're serious about performing your own validation you need to acquire and validate the file independently 
> to ensure trust in its content. Use the included copy at your own risk.


## Usage

### Using the Embedded Data
```go
package main

import (
    "github.com/nsmithuk/dnssec-root-anchors-go/anchors"
    "fmt"
)

func main() {
    // Get valid (not expired) DS records from the embedded XML
    dsRecords := anchors.GetValid()
    
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
    "github.com/nsmithuk/dnssec-root-anchors-go/anchors"
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
    dsRecords, err := anchors.ReadValid(xmlFile)
    if err != nil {
        panic(err)
    }
    
    // Print the DS records
    for _, record := range dsRecords {
        fmt.Println(record)
    }
}
```
If you want all records, not just valid ones, there is: `GetAll()` and `ReadAll(r io.Reader)`.

## Run the Tests

To run the tests for this project, use the following command:
```shell
go test ./...
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
