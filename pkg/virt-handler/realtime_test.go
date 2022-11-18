package virthandler

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Running real time workloads", func() {

	Context("captures the correct CPU ID from the thread command value", func() {
		DescribeTable("extracts the CPU ID", func(comm []byte, cpuID string, parseOK bool) {
			v, ok := isVCPU(comm)
			Expect(ok).To(Equal(parseOK))
			Expect(v).To(Equal(cpuID))
		},
			Entry("Extracts the CPU ID from a single digit vcpu pthread", []byte("CPU 3/KVM\n"), "3", true),
			Entry("Extracts the CPU ID from a double digit vcpu pthread", []byte("CPU 10/KVM\n"), "10", true),
			Entry("Fails to parse the comm value", []byte("vCPU 1/KVM\n"), "", false),
			Entry("Fails to parse a negative vCPU value", []byte("CPU -1/KVM\n"), "", false),
			Entry("Fails to parse a vCPU value that does not end with a carrier return", []byte("CPU 1/KVM"), "", false))
	})

	Context("determines if a vcpu is flagged for realtime", func() {
		DescribeTable("extracts the vcpu configuration", func(parsedMask cpuMask, vcpuID string, status maskType) {
			res := parsedMask.isRealtimeVCPU(vcpuID)
			Expect(res).To(BeEquivalentTo(status))
		},
			Entry("correctly returns a match as enabled", cpuMask{map[string]maskType{"0": enabled, "1": disabled}}, "0", enabled),
			Entry("correctly returns a match as disabled", cpuMask{map[string]maskType{"0": disabled, "1": disabled}}, "1", disabled),
			Entry("correctly returns a match when the map is empty", cpuMask{}, "1", enabled),
			Entry("fails to find the vcpu in the map", cpuMask{map[string]maskType{"0": disabled, "1": disabled}}, "2", disabled),
		)
	})

	Context("parses the vCPU mask", func() {
		DescribeTable("extracts the vCPU range", func(mask string, parsed cpuMask, err error) {
			m, e := parseCPUMask(mask)
			if err != nil {
				Expect(e).To(BeEquivalentTo(err))
				Expect(m).To(BeNil())
			} else {
				Expect(e).NotTo(HaveOccurred())
				Expect(*m).To(BeEquivalentTo(parsed))
			}
		},

			// Empty mask
			Entry("Empty mask", "", cpuMask{}, nil),
			// Invalid expressions
			Entry("Empty mask with spaces", "  ", nil, fmt.Errorf("invalid mask value '  ' in '  '")),
			Entry("Invalid expression", "a-b,33_", nil, fmt.Errorf("invalid mask value 'a-b' in 'a-b,33_'")),
			Entry("Invalid mask value", "3,3a", nil, fmt.Errorf("invalid mask value '3a' in '3,3a'")),
			Entry("invalid expression with spaces and a comma", "  ,   ", nil, fmt.Errorf("invalid mask value '  ' in '  ,   '")),
			Entry("Fails to parse a negative negate vcpu ID", "^-1", nil, fmt.Errorf("invalid mask value '^-1' in '^-1'")),
			Entry("Fails to extract a negate vCPU with a negative index", "^3,^-1", nil, fmt.Errorf("invalid mask value '^-1' in '^3,^-1'")),
			Entry("Fails to parse as the start range is smaller than the ending vcpu index id", "1-0", nil, fmt.Errorf("invalid mask range `1-0`")),
			Entry("Fails to match", "1-", nil, fmt.Errorf("invalid mask value '1-' in '1-'")),
			Entry("Fails to parse a negative vcpu ID", "-1", nil, fmt.Errorf("invalid mask value '-1' in '-1'")),
			Entry("Fails to parse a negative vcpu ID combined with a valid index", "0,-1", nil, fmt.Errorf("invalid mask value '-1' in '0,-1'")),
			// With range
			Entry("Extracts a single range with one core", "0-0", cpuMask{map[string]maskType{"0": enabled}}, nil),
			Entry("Extracts a single range multiple cores", "0-2", cpuMask{map[string]maskType{"0": enabled, "1": enabled, "2": enabled}}, nil),
			Entry("Extracts a multiple non overlapping ranges", "0-2,5-6", cpuMask{map[string]maskType{"0": enabled, "1": enabled, "2": enabled, "5": enabled, "6": enabled}}, nil),
			Entry("Extracts a multiple overlapping ranges", "0-2,2-3", cpuMask{map[string]maskType{"0": enabled, "1": enabled, "2": enabled, "3": enabled}}, nil),
			Entry("Extracts a single range with double digit vcpu IDs", "10-12", cpuMask{map[string]maskType{"10": enabled, "11": enabled, "12": enabled}}, nil),
			Entry("Extracts a multiple range with double digit vcpu IDs", "10-12,20,21", cpuMask{map[string]maskType{"10": enabled, "11": enabled, "12": enabled, "20": enabled, "21": enabled}}, nil),
			Entry("Extracts a multiple range with double digit vcpu IDs spaced in between", "10-12 ,  20,21", cpuMask{map[string]maskType{"10": enabled, "11": enabled, "12": enabled, "20": enabled, "21": enabled}}, nil),
			Entry("Extracts a single range prefixed and postfixed with spaces", "  0-2  ", cpuMask{map[string]maskType{"0": enabled, "1": enabled, "2": enabled}}, nil),
			Entry("Extracts a single range with a range of 1 vcpu only", "0-0", cpuMask{map[string]maskType{"0": enabled}}, nil),
			// Single vcpus
			Entry("Extracts a single vCPU index id", "0", cpuMask{map[string]maskType{"0": enabled}}, nil),
			Entry("Extracts a multiple single vCPU index ids", "0,1,2", cpuMask{map[string]maskType{"0": enabled, "1": enabled, "2": enabled}}, nil),
			Entry("Extracts a single double digit vcpu index id", "10", cpuMask{map[string]maskType{"10": enabled}}, nil),
			// Negate vcpus
			Entry("Extracts a single negate vCPU", "^3", cpuMask{map[string]maskType{"3": disabled}}, nil),
			Entry("Extracts a multiple negate vCPUs", "^0,^1", cpuMask{map[string]maskType{"0": disabled, "1": disabled}}, nil),
			Entry("Extracts a multiple overlapping negate vCPUs", "^0,^1,^0", cpuMask{map[string]maskType{"0": disabled, "1": disabled}}, nil),
			Entry("Extracts a double digit negate vCPU", "^13", cpuMask{map[string]maskType{"13": disabled}}, nil),
			Entry("Extracts a multiple double digit negate vCPU ids", "^13,^15", cpuMask{map[string]maskType{"13": disabled, "15": disabled}}, nil),
			// Combination of range and single Ids
			Entry("Extracts a single range and individual ID without overlaping index but in sequence", "0-2,3", cpuMask{map[string]maskType{"0": enabled, "1": enabled, "2": enabled, "3": enabled}}, nil),
			Entry("Extracts a single range and individual ID with overlaping index", "0-2,1", cpuMask{map[string]maskType{"0": enabled, "1": enabled, "2": enabled}}, nil),
			Entry("Extracts a single range and individual ID without overlaping but out of sequence", "5,1-2,6", cpuMask{map[string]maskType{"1": enabled, "2": enabled, "5": enabled, "6": enabled}}, nil),
			Entry("Extracts a single range and individual ID without overlaping but out of sequence with spaces", " 6 , 1-2 , 5 ", cpuMask{map[string]maskType{"1": enabled, "2": enabled, "5": enabled, "6": enabled}}, nil),
			// Combination of single Ids and negate index
			Entry("Extracts a single vCPU index with a negated id", "0,^1", cpuMask{map[string]maskType{"0": enabled, "1": disabled}}, nil),
			Entry("Extracts a multiple vCPU index and negated ids", "0,1,2,^3,^4", cpuMask{map[string]maskType{"0": enabled, "1": enabled, "2": enabled, "3": disabled, "4": disabled}}, nil),
			Entry("Extracts a multiple vCPU index with an overlapping negated id sandwitched in between", "0,^0,1", cpuMask{map[string]maskType{"0": disabled, "1": enabled}}, nil),
			Entry("Extracts a single vCPU index with overlapping negated id with negated as first entry", "^0,0", cpuMask{map[string]maskType{"0": disabled}}, nil),
			// Combination of range and negate index
			Entry("Extracts a single range and a negate id outside range", "0-2,^3", cpuMask{map[string]maskType{"0": enabled, "1": enabled, "2": enabled, "3": disabled}}, nil),
			Entry("Extracts a single range and a negate id within range", "0-2,^1", cpuMask{map[string]maskType{"0": enabled, "1": disabled, "2": enabled}}, nil),
			Entry("Extracts a multiple range and two negate ids within range", "^1,0-2, 3-6,^4 ", cpuMask{map[string]maskType{"0": enabled, "1": disabled, "2": enabled, "3": enabled, "4": disabled, "5": enabled, "6": enabled}}, nil),
			// Combination of all 3 expressions
			Entry("Extracts a single range, single index and negate ids without overlap", "^10,0-2,3", cpuMask{map[string]maskType{"0": enabled, "1": enabled, "2": enabled, "3": enabled, "10": disabled}}, nil),
			Entry("Extracts a multiple range, multiple index and multiple negate ids without overlap", "^1,0-2,^5,3,10,6-6", cpuMask{map[string]maskType{"0": enabled, "1": disabled, "2": enabled, "3": enabled, "5": disabled, "6": enabled, "10": enabled}}, nil),
			Entry("Extracts a multiple range, multiple index and negate ids with overlap", "^1,0-3,^3,4,5,6-8,^7", cpuMask{mask: map[string]maskType{"0": enabled, "1": disabled, "2": enabled, "3": disabled, "4": enabled, "5": enabled, "6": enabled, "7": disabled, "8": enabled}}, nil),
		)
	})

})
