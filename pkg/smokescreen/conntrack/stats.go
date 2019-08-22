package conntrack

import "time"

type InstrumentedConnStats struct {
	Id                       string    `json:"id"`
	Role                     string    `json:"role"`
	Rhost                    string    `json:"rhost"`
	Created                  time.Time `json:"created"`
	BytesIn                  uint64    `json:"bytesIn"`
	BytesOut                 uint64    `json:"bytesOut"`
	SecondsSinceLastActivity float64   `json:"secondsSinceLastActivity"`
}
