package rdns

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type route struct {
	types         []uint16
	class         uint16
	name          *regexp.Regexp
	source        *net.IPNet
	weekdays      []time.Weekday
	before        *TimeOfDay
	after         *TimeOfDay
	inverted      bool // invert the matching behavior
	dohPath       *regexp.Regexp
	resolver      Resolver
	listenerID    *regexp.Regexp
	tlsServerName *regexp.Regexp
}

// NewRoute initializes a route from string parameters.
func NewRoute(name, class string, types, weekdays []string, before, after, source, dohPath, listenerID, tlsServerName string, resolver Resolver) (*route, error) {
	if resolver == nil {
		return nil, errors.New("no resolver defined for route")
	}
	t, err := stringToType(types)
	if err != nil {
		return nil, err
	}
	w, err := stringsToWeekdays(weekdays)
	if err != nil {
		return nil, err
	}
	b, err := parseTimeOfDay(before)
	if err != nil {
		return nil, err
	}
	a, err := parseTimeOfDay(after)
	if err != nil {
		return nil, err
	}
	c, err := stringToClass(class)
	if err != nil {
		return nil, err
	}
	re, err := regexp.Compile(name)
	if err != nil {
		return nil, err
	}
	dohRe, err := regexp.Compile(dohPath)
	if err != nil {
		return nil, err
	}
	listenerRe, err := regexp.Compile(listenerID)
	if err != nil {
		return nil, err
	}
	tlsRe, err := regexp.Compile(tlsServerName)
	if err != nil {
		return nil, err
	}
	var sNet *net.IPNet
	if source != "" {
		_, sNet, err = net.ParseCIDR(source)
		if err != nil {
			return nil, err
		}
	}
	return &route{
		types:         t,
		class:         c,
		name:          re,
		weekdays:      w,
		before:        b,
		after:         a,
		source:        sNet,
		dohPath:       dohRe,
		listenerID:    listenerRe,
		tlsServerName: tlsRe,
		resolver:      resolver,
	}, nil
}

func (r *route) match(q *dns.Msg, ci ClientInfo) bool {
	question := q.Question[0]
	if !r.matchType(question.Qtype) {
		return r.inverted
	}
	if r.class != 0 && r.class != question.Qclass {
		return r.inverted
	}
	if !r.name.MatchString(question.Name) {
		return r.inverted
	}
	if r.source != nil && !r.source.Contains(ci.SourceIP) {
		return r.inverted
	}
	if !r.dohPath.MatchString(ci.DoHPath) {
		return r.inverted
	}
	if !r.listenerID.MatchString(ci.Listener) {
		return r.inverted
	}
	if !r.tlsServerName.MatchString(ci.TLSServerName) {
		return r.inverted
	}
	if len(r.weekdays) > 0 || r.before != nil || r.after != nil {
		now := time.Now().Local()
		hour := now.Hour()
		minute := now.Minute()
		if len(r.weekdays) > 0 {
			weekday := now.Weekday()
			var weekdayMatch bool
			for _, wd := range r.weekdays {
				if weekday == wd {
					weekdayMatch = true
					break
				}
			}
			if !weekdayMatch {
				return r.inverted
			}
		}
		if r.before != nil && !r.before.isAfter(hour, minute) {
			return r.inverted
		}
		if r.after != nil && !r.after.isBefore(hour, minute) {
			return r.inverted
		}
	}
	return !r.inverted
}

func (r *route) Invert(value bool) {
	r.inverted = value
}

func (r *route) String() string {
	if r.isDefault() {
		return "(default)"
	}
	var fragments []string
	if len(r.types) > 0 {
		var types []string
		for _, t := range r.types {
			types = append(types, dns.TypeToString[t])
		}
		fragments = append(fragments, fmt.Sprintf("types=%v", types))
	}
	if r.name.String() != "" {
		fragments = append(fragments, "name="+r.name.String())
	}
	if r.class != 0 {
		s, _ := classToString(r.class)
		fragments = append(fragments, "class="+s)
	}
	if r.source != nil {
		fragments = append(fragments, "source="+r.source.String())
	}
	if r.dohPath.String() != "" {
		fragments = append(fragments, "doh-path="+r.dohPath.String())
	}
	if r.listenerID.String() != "" {
		fragments = append(fragments, "listener="+r.listenerID.String())
	}
	if r.tlsServerName.String() != "" {
		fragments = append(fragments, "servername="+r.tlsServerName.String())
	}
	if len(r.weekdays) > 0 {
		fragments = append(fragments, fmt.Sprintf("weekdays=%v", r.weekdays))
	}
	if r.after != nil {
		fragments = append(fragments, "after="+r.after.String())
	}
	if r.before != nil {
		fragments = append(fragments, "before="+r.before.String())
	}
	if r.inverted {
		fragments = append(fragments, "invert=true")
	}
	return "(" + strings.Join(fragments, ",") + ")"
}

func (r *route) isDefault() bool {
	return r.class == 0 && len(r.types) == 0 && r.name.String() == ""
}

func (r *route) matchType(typ uint16) bool {
	if len(r.types) == 0 {
		return true
	}
	for _, t := range r.types {
		if t == typ {
			return true
		}
	}
	return false
}

// Convert DNS type strings into the numerical type, for example "A" -> 1.
func stringToType(s []string) ([]uint16, error) {
	if len(s) == 0 {
		return nil, nil
	}
	var types []uint16
loop:
	for _, typ := range s {
		for k, v := range dns.TypeToString {
			if v == strings.ToUpper(typ) {
				types = append(types, k)
				continue loop
			}
		}
		return nil, fmt.Errorf("unknown type '%s'", s)
	}
	return types, nil
}

// Convert a DNS class string into its numerical form, for example "INET" -> 1.
func stringToClass(s string) (uint16, error) {
	switch strings.ToUpper(s) {
	case "":
		return 0, nil
	case "IN", "INET":
		return 1, nil
	case "CH":
		return 3, nil
	case "HS":
		return 4, nil
	case "NONE":
		return 254, nil
	case "ANY":
		return 255, nil
	default:
		return 0, fmt.Errorf("unknown class '%s'", s)
	}
}

// Convert a DNS class identifier into its string from, for example 1 -> "INET".
func classToString(class uint16) (string, error) {
	switch class {
	case 1:
		return "IN", nil
	case 3:
		return "CH", nil
	case 4:
		return "HS", nil
	case 254:
		return "NONE", nil
	case 255:
		return "ANY", nil
	default:
		return "", fmt.Errorf("unknown class identifier %d", class)
	}
}

func stringsToWeekdays(weekdays []string) ([]time.Weekday, error) {
	var result []time.Weekday
	for _, day := range weekdays {
		var weekday time.Weekday
		switch day {
		case "mon":
			weekday = time.Monday
		case "tue":
			weekday = time.Tuesday
		case "wed":
			weekday = time.Wednesday
		case "thu":
			weekday = time.Thursday
		case "fri":
			weekday = time.Friday
		case "sat":
			weekday = time.Saturday
		case "sun":
			weekday = time.Sunday
		default:
			return nil, fmt.Errorf("unrecognized weekday %q, must be 'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'", day)
		}
		result = append(result, weekday)
	}
	return result, nil
}

type TimeOfDay struct {
	hour, minute int
}

func parseTimeOfDay(t string) (*TimeOfDay, error) {
	if t == "" {
		return nil, nil
	}
	f := strings.SplitN(t, ":", 2)
	hour, err := strconv.Atoi(f[0])
	if err != nil {
		return nil, err
	}
	var min int
	if len(f) > 1 {
		min, err = strconv.Atoi(f[1])
		if err != nil {
			return nil, err
		}
	}
	return &TimeOfDay{
		hour:   hour,
		minute: min,
	}, nil
}

func (t *TimeOfDay) isBefore(hour, minute int) bool {
	return t.hour < hour || (t.hour == hour && t.minute <= minute)
}

func (t *TimeOfDay) isAfter(hour, minute int) bool {
	return t.hour > hour || (t.hour == hour && t.minute > minute)
}

func (t *TimeOfDay) String() string {
	return fmt.Sprintf("%2d:%2d", t.hour, t.minute)
}
