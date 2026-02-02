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
	ips, err := LoadKnownDNS(dataDir, country)
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

type CIDRSource struct {
	country string
	mode    string
	blocks  []string
}

func NewCIDRSource(dataDir, country, mode string) (*CIDRSource, error) {
	if !CIDRBlocksExist(dataDir, country) {
		if err := DownloadCIDRBlocks(dataDir, country); err != nil {
			return nil, err
		}
	}
	blocks, err := LoadCIDRBlocks(dataDir, country)
	if err != nil {
		return nil, err
	}
	return &CIDRSource{country: country, mode: mode, blocks: blocks}, nil
}

func (s *CIDRSource) IPs() <-chan string {
	return ExpandCIDR(s.blocks, s.mode)
}

func (s *CIDRSource) Count() int {
	return CountCIDRIPs(s.blocks, s.mode)
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

