package vultr

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/libdns/libdns"
	"github.com/vultr/govultr/v3"
)

// Converts `govultr.DomainRecord` to `libdns.Record“
// Taken from libdns/cloudflare, adapted for Vultr's specific format
func libdnsRecord(r govultr.DomainRecord, zone string) (libdns.Record, error) {
	name := libdns.RelativeName(r.Name, zone)
	ttl := time.Duration(r.TTL) * time.Second

	switch r.Type {
	case "A", "AAAA":
		addr, err := netip.ParseAddr(r.Data)
		if err != nil {
			return libdns.Address{}, fmt.Errorf("invalid IP address %q: %v", r.Data, err)
		}

		return libdns.Address{
			Name:         name,
			TTL:          ttl,
			IP:           addr,
			ProviderData: r.ID,
		}, nil
	case "CAA":
		dataParts := strings.SplitN(r.Data, " ", 3)
		if len(dataParts) < 3 {
			return libdns.SRV{}, fmt.Errorf("record %v does not contain enough data fields; expected format: '<flags> <tag> <value>'", name)
		}

		flags, err := strconv.Atoi(dataParts[0])
		if err != nil {
			return libdns.SRV{}, fmt.Errorf("record %v contains invalid value for flags: %v", name, err)
		}

		return libdns.CAA{
			Name:         name,
			TTL:          ttl,
			Flags:        uint8(flags),
			Tag:          dataParts[1],
			Value:        dataParts[2],
			ProviderData: r.ID,
		}, nil
	case "CNAME":
		return libdns.CNAME{
			Name:         name,
			TTL:          ttl,
			Target:       r.Data,
			ProviderData: r.ID,
		}, nil
	case "MX":
		return libdns.MX{
			Name:         name,
			TTL:          ttl,
			Preference:   uint16(r.Priority),
			Target:       r.Data,
			ProviderData: r.ID,
		}, nil
	case "NS":
		return libdns.NS{
			Name:         name,
			TTL:          ttl,
			Target:       r.Data,
			ProviderData: r.ID,
		}, nil
	case "SRV":
		// Vultr doesn't append the zone to the SRV record name, so we just need
		// to parse 2 parts
		parts := strings.SplitN(r.Name, ".", 2)
		if len(parts) < 2 {
			return libdns.SRV{}, fmt.Errorf("name %v does not contain enough fields; expected format: '_service._proto.name'", name)
		}

		dataParts := strings.SplitN(r.Data, " ", 3)
		if len(dataParts) < 3 {
			return libdns.SRV{}, fmt.Errorf("record %v does not contain enough data fields; expected format: 'weight port target'", name)
		}

		weight, err := strconv.Atoi(dataParts[0])
		if err != nil {
			return libdns.SRV{}, fmt.Errorf("record %v contains invalid value for weight: %v", name, err)
		}

		port, err := strconv.Atoi(dataParts[1])
		if err != nil {
			return libdns.SRV{}, fmt.Errorf("record %v contains invalid value for port: %v", name, err)
		}

		return libdns.SRV{
			Service:      strings.TrimPrefix(parts[0], "_"),
			Transport:    strings.TrimPrefix(parts[1], "_"),
			Name:         zone,
			TTL:          ttl,
			Priority:     uint16(r.Priority),
			Weight:       uint16(weight),
			Port:         uint16(port),
			Target:       dataParts[2],
			ProviderData: r.ID,
		}, nil
	case "TXT":
		return libdns.TXT{
			Name:         name,
			TTL:          ttl,
			Text:         r.Data,
			ProviderData: r.ID,
		}, nil
	default:
		return libdns.RR{
			Name: name,
			TTL:  ttl,
			Type: r.Type,
			Data: r.Data,
		}.Parse()
	}
}

// Converts `libdns.Record` to `govultr.DomainRecordReq`, to be used with API
// requests.
func vultrRecordReq(r libdns.Record) (govultr.DomainRecordReq, error) {
	return govultr.DomainRecordReq{
		Name: r.RR().Name,
		Type: r.RR().Type,
		TTL:  int(r.RR().TTL.Seconds()),
		Data: r.RR().Data,
	}, nil
}

func GetRecordID(r libdns.Record) (string, error) {
	var recordId string

	switch r := r.(type) {
	case libdns.Address:
		recordId = r.ProviderData.(string)
		return recordId, nil
	case libdns.CAA:
		recordId = r.ProviderData.(string)
		return recordId, nil
	case libdns.CNAME:
		recordId = r.ProviderData.(string)
		return recordId, nil
	case libdns.MX:
		recordId = r.ProviderData.(string)
		return recordId, nil
	case libdns.NS:
		recordId = r.ProviderData.(string)
		return recordId, nil
	case libdns.SRV:
		recordId = r.ProviderData.(string)
		return recordId, nil
	case libdns.ServiceBinding:
		recordId = r.ProviderData.(string)
		return recordId, nil
	case libdns.TXT:
		recordId = r.ProviderData.(string)
		return recordId, nil
	default:
	}

	return "", fmt.Errorf("libdns record has no provider record ID")
}
