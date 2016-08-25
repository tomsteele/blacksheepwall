package bsw

import (
	"encoding/binary"
	"net"
)

// DomainRegex is used to validate a hostname to ensure it is legitimate.
var DomainRegex = `^\.?[a-z\d]+(?:(?:[a-z\d]*)|(?:[a-z\d\-]*[a-z\d]))(?:\.[a-z\d]+(?:(?:[a-z\d]*)|(?:[a-z\d\-]*[a-z\d])))*$`

// Tsk is used to return the results of a task to the caller.
type Tsk struct {
	task    string
	results []Result
	errs    []error
}

func newTsk(task string) *Tsk {
	return &Tsk{task: task}
}

// Task returns the descriptive name of a task.
func (t *Tsk) Task() string {
	return t.task
}

// SetTask will set the task.
func (t *Tsk) SetTask(task string) {
	t.task = task
}

// AddResult adds a result to results.
func (t *Tsk) AddResult(ip, hostname string) {
	t.results = append(t.results, Result{
		Source:   t.task,
		IP:       ip,
		Hostname: hostname,
	})
}

// HasResults return true if len of results is greater than 0.
func (t *Tsk) HasResults() bool {
	return len(t.results) > 0
}

// Err returns the value of err.
func (t *Tsk) Err() []error {
	return t.errs
}

// SetErr sets the value of err
func (t *Tsk) SetErr(err error) {
	t.errs = append(t.errs, err)
}

// Results returns the results.
func (t *Tsk) Results() []Result {
	return t.results
}

// Result is used to store a single IP and Hostname record.
type Result struct {
	Source   string `json:"src"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// Results is a slice of Result.
type Results []Result

func (r Results) Len() int      { return len(r) }
func (r Results) Swap(i, j int) { r[i], r[j] = r[j], r[i] }

// Sorts by IPv4 address, IPv6 addresses will be show first and will be unsorted.
func (r Results) Less(i, j int) bool {
	first := net.ParseIP(r[i].IP).To4()
	second := net.ParseIP(r[j].IP).To4()
	if first == nil {
		return true
	}
	if second == nil {
		return false
	}
	return binary.BigEndian.Uint32(first) < binary.BigEndian.Uint32(second)
}

func removeDuplicates(in []string) []string {
	m := map[string]bool{}
	out := []string{}
	for _, i := range in {
		if i == "" {
			continue
		}
		if _, ok := m[i]; ok {
			continue
		}
		m[i] = true
		out = append(out, i)
	}
	return out
}
