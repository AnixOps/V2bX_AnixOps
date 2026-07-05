package panel

import "time"

type NodeLogEntry struct {
	Level      string
	Source     string
	Message    string
	Timestamp  time.Time
	TraceID    string
	FieldsJSON string
}
