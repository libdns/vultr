package vultr

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/oauth2"

	"github.com/libdns/libdns"
	"github.com/vultr/govultr/v3"
)

type Client struct {
	vultr *govultr.Client
	mutex sync.Mutex
}

func (p *Provider) getClient() error {
	if p.client.vultr == nil {
		oauth_cfg := &oauth2.Config{}
		oauth_token_source := oauth_cfg.TokenSource(context.TODO(), &oauth2.Token{AccessToken: p.APIToken})

		p.client.vultr = govultr.NewClient(oauth2.NewClient(context.TODO(), oauth_token_source))
	}

	return nil
}

func (p *Provider) getDNSEntries(ctx context.Context, domain string) ([]libdns.Record, error) {
	p.getClient()

	listOptions := &govultr.ListOptions{}

	var records []libdns.Record
	for {
		dns_entries, meta, _, err := p.client.vultr.DomainRecord.List(ctx, domain, listOptions)
		if err != nil {
			return records, err
		}

		for _, entry := range dns_entries {
			record := fromAPIRecord(entry, domain)
			records = append(records, record)
		}

		if meta.Links.Next == "" {
			break
		}

		listOptions.Cursor = meta.Links.Next
	}

	return records, nil
}

func (p *Provider) addDNSRecord(ctx context.Context, domain string, r libdns.Record) (libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	p.getClient()

	domainRecordReq := toDomainRecordReq(r)

	rec, _, err := p.client.vultr.DomainRecord.Create(ctx, domain, &domainRecordReq)
	if err != nil {
		return r, err
	}

	record := fromLibdnsRecord(r, rec.ID)

	return record, nil
}

func (p *Provider) removeDNSRecord(ctx context.Context, domain string, record libdns.Record) (libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	p.getClient()

	recordId, err := getRecordId(record)
	if err != nil {
		// try to get the ID from API if we don't have it
		records, err := p.getDNSEntries(ctx, domain)
		if err != nil {
			return record, fmt.Errorf("could not get record ID from API")
		}

		for _, rec := range records {
			if rec.RR().Name == record.RR().Name {
				fmt.Println(rec)
				recordId = rec.(VultrRecord).ID
			}
		}
	}

	err = p.client.vultr.DomainRecord.Delete(ctx, domain, recordId)
	if err != nil {
		return record, err
	}

	return record, nil
}

func (p *Provider) updateDNSRecord(ctx context.Context, domain string, record libdns.Record) (libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	p.getClient()

	recordId, err := getRecordId(record)
	if err != nil {
		// try to get the ID from API if we don't have it
		records, err := p.getDNSEntries(ctx, domain)
		if err != nil {
			return record, fmt.Errorf("could not get record ID from API")
		}

		for _, rec := range records {
			if rec.RR().Data == record.RR().Data {
				recordId = rec.(VultrRecord).ID
			}
		}
	}

	domainRecordReq := toDomainRecordReq(record)

	err = p.client.vultr.DomainRecord.Update(ctx, domain, recordId, &domainRecordReq)
	if err != nil {
		return record, err
	}

	return record, nil
}

func (p *Provider) getDNSZones(ctx context.Context) ([]libdns.Zone, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	p.getClient()

	listOptions := &govultr.ListOptions{}

	var zones []libdns.Zone
	for {
		dns_zones, meta, _, err := p.client.vultr.Domain.List(ctx, listOptions)
		if err != nil {
			return zones, err
		}

		for _, entry := range dns_zones {
			zone := libdns.Zone{
				Name: entry.Domain,
			}
			zones = append(zones, zone)
		}

		if meta.Links.Next == "" {
			break
		}

		listOptions.Cursor = meta.Links.Next
	}

	return zones, nil
}
