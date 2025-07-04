# Vultr for `libdns`


This package implements the libdns interfaces for the [Vultr API](https://www.vultr.com/api/) (using the Go library client from: https://github.com/vultr/govultr)

## Authenticating

To authenticate you need to supply a Vultr API token.

## Example

Here's a minimal example of how to get all your DNS records using this `libdns` provider (see `_example/main.go`)

```go
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/libdns/libdns"

	"github.com/libdns/vultr"
)

func main() {
	token := os.Getenv("VULTR_API_TOKEN")
	if token == "" {
		fmt.Printf("VULTR_API_TOKEN not set\n")
		return
	}
	zone := os.Getenv("ZONE")
	if zone == "" {
		fmt.Printf("ZONE not set\n")
		return
	}

	provider := vultr.Provider{APIToken: token}

	zones, err := provider.ListZones(context.TODO())
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}

	for _, zone := range zones {
		fmt.Printf("%s\n", zone.Name)
	}

	records, err := provider.GetRecords(context.TODO(), zone)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
	}

	testName := "libdns-test"
	testId := ""
	for _, record := range records {
		fmt.Printf("%s (.%s): %s, %s\n", record.RR().Name, zone, record.RR().Data, record.RR().Type)

		recordId, err := vultr.GetRecordID(record)
		if err != nil {
			fmt.Printf("ERROR: %s\n", err.Error())
		}

		if record.RR().Name == testName {
			testId = recordId
		}
	}

	if testId != "" {
		// fmt.Printf("Delete entry for %s (id:%s)\n", testName, testId)
		// _, err = provider.DeleteRecords(context.TODO(), zone, []libdns.Record{libdns.Record{
		// 	ID: testId,
		// }})
		// if err != nil {
		// 	fmt.Printf("ERROR: %s\n", err.Error())
		// }
		// Set only works if we have a record.ID
		fmt.Printf("Replacing entry for %s\n", testName)
		_, err = provider.SetRecords(context.TODO(), zone, []libdns.Record{libdns.TXT{
			Name:         testName,
			Text:         fmt.Sprintf("Replacement test entry created by libdns %s", time.Now()),
			TTL:          time.Duration(30) * time.Second,
			ProviderData: testId,
		}})
		if err != nil {
			fmt.Printf("ERROR: %s\n", err.Error())
		}
	} else {
		fmt.Printf("Creating new entry for %s\n", testName)
		_, err = provider.AppendRecords(context.TODO(), zone, []libdns.Record{libdns.RR{
			Type: "TXT",
			Name: testName,
			Data: fmt.Sprintf("This is a test entry created by libdns %s", time.Now()),
			TTL:  time.Duration(30) * time.Second,
		}})
		if err != nil {
			fmt.Printf("ERROR: %s\n", err.Error())
		}
	}
}
```
