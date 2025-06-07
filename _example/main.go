package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/libdns/libdns"
	"github.com/libdns/vultr/v2"
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
	shouldCleanup := os.Getenv("DELETE_RECORDS") == "true"

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

		if record.RR().Name == testName {
			testId = record.(vultr.VultrRecord).ID
		}
	}

	if testId != "" {
		if shouldCleanup {
			fmt.Printf("Delete entry for %s (id:%s)\n", testName, testId)
			_, err = provider.DeleteRecords(context.TODO(), zone, []libdns.Record{vultr.VultrRecord{
				ID: testId,
			}})
			if err != nil {
				fmt.Printf("ERROR: %s\n", err.Error())
			}
		} else {
			// Set only works if we have a record.ID
			fmt.Printf("Replacing entry for %s\n", testName)
			_, err = provider.SetRecords(context.TODO(), zone, []libdns.Record{vultr.VultrRecord{
				Record: libdns.RR{
					Name: testName,
					Type: "TXT",
					Data: fmt.Sprintf("Replacement test entry created by libdns %s", time.Now()),
					TTL:  time.Duration(90) * time.Second,
				},
				ID: testId,
			}})
			if err != nil {
				fmt.Printf("ERROR: %s\n", err.Error())
			}
		}
	} else {
		fmt.Printf("Creating new entry for %s\n", testName)
		_, err = provider.AppendRecords(context.TODO(), zone, []libdns.Record{vultr.VultrRecord{
			Record: libdns.RR{
				Type: "TXT",
				Name: testName,
				Data: fmt.Sprintf("This is a test entry created by libdns %s", time.Now()),
				TTL:  time.Duration(60) * time.Second,
			},
			ID: testId,
		}})
		if err != nil {
			fmt.Printf("ERROR: %s\n", err.Error())
		}
	}
}
