package main

type IPSource interface {
	IPs() <-chan string
	Count() int
}

type FileSource struct {
	path string
	ips  []string
}

func NewFileSource(path string) (*FileSource, error) {
	ips, err := loadLines(path)
	if err != nil {
		return nil, err
	}
	return &FileSource{path: path, ips: ips}, nil
}

func (s *FileSource) IPs() <-chan string {
	return sliceToChannel(s.ips)
}

func (s *FileSource) Count() int {
	return len(s.ips)
}

type DNSListSource struct {
	country string
	ips     []string
}

func NewDNSListSource(dataDir, country string) (*DNSListSource, error) {
	ips, err := LoadDNSList(dataDir, country)
	if err != nil {
		return nil, err
	}
	return &DNSListSource{country: country, ips: ips}, nil
}

func (s *DNSListSource) IPs() <-chan string {
	return sliceToChannel(s.ips)
}

func (s *DNSListSource) Count() int {
	return len(s.ips)
}

type RangeSource struct {
	country string
	mode    string
	ranges  []string
}

func NewRangeSource(dataDir, country, mode string) (*RangeSource, error) {
	ranges, err := LoadRanges(dataDir, country)
	if err != nil {
		return nil, err
	}
	return &RangeSource{country: country, mode: mode, ranges: ranges}, nil
}

func (s *RangeSource) IPs() <-chan string {
	return ExpandRangesWithMode(s.ranges, s.mode)
}

func (s *RangeSource) Count() int {
	return CountIPsWithMode(s.ranges, s.mode)
}

func sliceToChannel(ips []string) <-chan string {
	ch := make(chan string, len(ips))
	go func() {
		defer close(ch)
		for _, ip := range ips {
			ch <- ip
		}
	}()
	return ch
}

