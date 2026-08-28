package platform

import (
	"reflect"
	"sort"
	"testing"
)

func TestHugepageSizeToKB(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		wantErr  bool
	}{
		{
			name:     "2MB format",
			input:    "2M",
			expected: 2048,
			wantErr:  false,
		},
		{
			name:     "1GB format",
			input:    "1G",
			expected: 1048576,
			wantErr:  false,
		},
		{
			name:     "2048kB format",
			input:    "2048kB",
			expected: 2048,
			wantErr:  false,
		},
		{
			name:     "2048k format",
			input:    "2048k",
			expected: 2048,
			wantErr:  false,
		},
		{
			name:     "plain number (assumed kB)",
			input:    "2048",
			expected: 2048,
			wantErr:  false,
		},
		{
			name:     "lowercase m",
			input:    "2m",
			expected: 2048,
			wantErr:  false,
		},
		{
			name:     "lowercase g",
			input:    "1g",
			expected: 1048576,
			wantErr:  false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "invalid unit",
			input:    "2X",
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "non-numeric",
			input:    "abc",
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := hugepageSizeToKB(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("expected %d, got %d", tt.expected, result)
				}
			}
		})
	}
}

func TestParseHugepageSizes(t *testing.T) {
	tests := []struct {
		name     string
		cmdline  string
		expected []int
	}{
		{
			name:     "single 2MB hugepage",
			cmdline:  "console=ttyS0 hugepagesz=2M hugepages=1024",
			expected: []int{2048},
		},
		{
			name:     "single 1GB hugepage",
			cmdline:  "console=ttyS0 hugepagesz=1G hugepages=4",
			expected: []int{1048576},
		},
		{
			name:     "multiple hugepage sizes",
			cmdline:  "console=ttyS0 hugepagesz=2M hugepages=1024 hugepagesz=1G hugepages=4",
			expected: []int{2048, 1048576},
		},
		{
			name:     "default_hugepagesz",
			cmdline:  "console=ttyS0 default_hugepagesz=2M hugepages=1024",
			expected: []int{2048},
		},
		{
			name:     "both default and explicit",
			cmdline:  "default_hugepagesz=2M hugepagesz=1G hugepages=4",
			expected: []int{2048, 1048576},
		},
		{
			name:     "no hugepages configured",
			cmdline:  "console=ttyS0 quiet splash",
			expected: []int{},
		},
		{
			name:     "duplicate sizes (should deduplicate)",
			cmdline:  "hugepagesz=2M hugepages=512 hugepagesz=2M hugepages=512",
			expected: []int{2048},
		},
		{
			name:     "hugepages param without hugepagesz",
			cmdline:  "console=ttyS0 hugepages=1024",
			expected: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHugepageSizes(tt.cmdline)
			// Sort both slices for comparison
			sort.Ints(result)
			expectedSorted := make([]int, len(tt.expected))
			copy(expectedSorted, tt.expected)
			sort.Ints(expectedSorted)
			// Handle empty slice comparison (nil vs []int{})
			if len(result) == 0 && len(expectedSorted) == 0 {
				return
			}
			if !reflect.DeepEqual(result, expectedSorted) {
				t.Errorf("expected %v, got %v", expectedSorted, result)
			}
		})
	}
}
