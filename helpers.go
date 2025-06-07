package vultr

import (
	"fmt"
	"strings"
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

	// Vultr uses a custom priority field for MX and SRV records
	data := r.Data
	if r.Type == "MX" {
		data = fmt.Sprintf("%d %s", r.Priority, r.Data)
	} else if r.Type == "SRV" {
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
	data := r.RR().Data
	var priority int

	// Vultr uses a custom priority field for MX and SRV records
	if rec, ok := r.RR().Parse(); ok == nil {
		if r.RR().Type == "MX" {
			mx := rec.(libdns.MX)
			priority = int(mx.Preference)
			data = mx.Target
		} else if r.RR().Type == "SRV" {
			srv := rec.(libdns.SRV)
			priority = int(srv.Priority)
			data = data[strings.Index(data, " ")+1:]
		}
	}

	rr := r.RR()
	return govultr.DomainRecordReq{
		Name:     rr.Name,
		Type:     rr.Type,
		TTL:      int(rr.TTL.Seconds()),
		Data:     data,
		Priority: &priority,
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
