package vultr

import (
	"fmt"
	"time"

	"github.com/libdns/libdns"
	"github.com/vultr/govultr/v3"
)

type VultrRecord struct {
	Record libdns.RR
	ID     string
}

func (r VultrRecord) RR() libdns.RR {
	return r.Record
}

// Converts a govultr.DomainRecord to libdns.Record
// Taken from libdns/digitalocean
func fromAPIRecord(r govultr.DomainRecord, zone string) VultrRecord {
	name := libdns.RelativeName(r.Name, zone)
	ttl := time.Duration(r.TTL) * time.Second

	// Vultr uses a custom priority field for MX records
	data := r.Data
	if r.Type == "MX" {
		data = fmt.Sprintf("%d %s", r.Priority, r.Data)
	}

	return VultrRecord{
		Record: libdns.RR{
			Name: name,
			TTL:  ttl,
			Type: r.Type,
			Data: data,
		},
		ID: r.ID,
	}
}

// Converts a libdns.Record to VultrRecord with an optional ID
func fromLibdnsRecord(r libdns.Record, id string) VultrRecord {
	rr := r.RR()
	return VultrRecord{
		Record: rr,
		ID:     id,
	}
}

// Converts a libdns.Record to a govultr.DomainRecordReq
func toDomainRecordReq(r libdns.Record) govultr.DomainRecordReq {
	rr := r.RR()
	return govultr.DomainRecordReq{
		Name: rr.Name,
		Type: rr.Type,
		TTL:  int(rr.TTL.Seconds()),
		Data: rr.Data,
	}
}

func getRecordId(r libdns.Record) (string, error) {
	var id string
	if vr, err := r.(VultrRecord); err {
		id = vr.ID
	}

	if id == "" {
		return "", fmt.Errorf("record has no ID: %v", r)
	}

	return id, nil
}
