package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Test case structure
type TestCase struct {
	name              string
	message           string
	expectedMatches   []string
	expectedPublic    []bool
	expectedImmediate []bool
	expectedTicketIDs []string
}

func main() {
	fmt.Println("=== Comprehensive Test for Jira Ticket Regex and Public Visibility Logic ===\n")

	// Test the exact regex pattern from the main application
	jiraTicketRegex := regexp.MustCompile(`(^|[^A-Za-z0-9-!])([\$#%]*[A-Z]+-[0-9]+!?)(?:[^A-Za-z0-9-!]|$)`)

	testCases := []TestCase{
		{
			name:              "Original webhook message with #TICKETID",
			message:           "adjust metrics to be queried from port 80 #PROJECTID-1337\n",
			expectedMatches:   []string{"#PROJECTID-1337"},
			expectedPublic:    []bool{true},
			expectedImmediate: []bool{false},
			expectedTicketIDs: []string{"PROJECTID-1337"},
		},
		{
			name:              "Original webhook message with $TICKETID",
			message:           "adjust metrics to be queried from port 80 $PROJECTID-1337\n",
			expectedMatches:   []string{"$PROJECTID-1337"},
			expectedPublic:    []bool{true},
			expectedImmediate: []bool{false},
			expectedTicketIDs: []string{"PROJECTID-1337"},
		},
		{
			name:              "Original webhook message without prefix",
			message:           "adjust metrics to be queried from port 80 PROJECTID-1337\n",
			expectedMatches:   []string{"PROJECTID-1337"},
			expectedPublic:    []bool{false},
			expectedImmediate: []bool{false},
			expectedTicketIDs: []string{"PROJECTID-1337"},
		},
		{
			name:              "Immediate posting with %TICKETID",
			message:           "Fix urgent issue %URGENT-999 immediately",
			expectedMatches:   []string{"%URGENT-999"},
			expectedPublic:    []bool{false},
			expectedImmediate: []bool{true},
			expectedTicketIDs: []string{"URGENT-999"},
		},
		{
			name:              "Immediate public with #%TICKETID",
			message:           "Critical fix for #%CRIT-123",
			expectedMatches:   []string{"#%CRIT-123"},
			expectedPublic:    []bool{true},
			expectedImmediate: []bool{true},
			expectedTicketIDs: []string{"CRIT-123"},
		},
		{
			name:              "Immediate public with $%TICKETID",
			message:           "Emergency patch $%EMERG-456",
			expectedMatches:   []string{"$%EMERG-456"},
			expectedPublic:    []bool{true},
			expectedImmediate: []bool{true},
			expectedTicketIDs: []string{"EMERG-456"},
		},
		{
			name:              "Immediate public with %#TICKETID",
			message:           "Hotfix for %#HOT-789",
			expectedMatches:   []string{"%#HOT-789"},
			expectedPublic:    []bool{true},
			expectedImmediate: []bool{true},
			expectedTicketIDs: []string{"HOT-789"},
		},
		{
			name:              "Immediate public with %$TICKETID",
			message:           "Quick fix %$QUICK-321",
			expectedMatches:   []string{"%$QUICK-321"},
			expectedPublic:    []bool{true},
			expectedImmediate: []bool{true},
			expectedTicketIDs: []string{"QUICK-321"},
		},
		{
			name:              "Multiple tickets with mixed prefixes including %",
			message:           "Fix bugs for #PROJ-123 and $TASK-456, %URGENT-999 and #%CRIT-111",
			expectedMatches:   []string{"#PROJ-123", "$TASK-456", "%URGENT-999", "#%CRIT-111"},
			expectedPublic:    []bool{true, true, false, true},
			expectedImmediate: []bool{false, false, true, true},
			expectedTicketIDs: []string{"PROJ-123", "TASK-456", "URGENT-999", "CRIT-111"},
		},
		{
			name:              "Edge case: ticket at start of line",
			message:           "#ABC-123 should be public",
			expectedMatches:   []string{"#ABC-123"},
			expectedPublic:    []bool{true},
			expectedImmediate: []bool{false},
			expectedTicketIDs: []string{"ABC-123"},
		},
		{
			name:              "Edge case: ticket at end of line with %",
			message:           "See ticket %XYZ-999",
			expectedMatches:   []string{"%XYZ-999"},
			expectedPublic:    []bool{false},
			expectedImmediate: []bool{true},
			expectedTicketIDs: []string{"XYZ-999"},
		},
		{
			name:              "Edge case: ticket with newline",
			message:           "Related to #TEST-555\nAnother line",
			expectedMatches:   []string{"#TEST-555"},
			expectedPublic:    []bool{true},
			expectedImmediate: []bool{false},
			expectedTicketIDs: []string{"TEST-555"},
		},
		{
			name:              "No matches",
			message:           "This has no ticket references at all",
			expectedMatches:   []string{},
			expectedPublic:    []bool{},
			expectedImmediate: []bool{},
			expectedTicketIDs: []string{},
		},
		{
			name:              "False positive test: embedded in URL",
			message:           "Visit http://example.com/PROJ-123 for info",
			expectedMatches:   []string{"PROJ-123"},
			expectedPublic:    []bool{false},
			expectedImmediate: []bool{false},
			expectedTicketIDs: []string{"PROJ-123"},
		},
		{
			name:              "Case sensitivity test",
			message:           "lowercase proj-123 should not match",
			expectedMatches:   []string{},
			expectedPublic:    []bool{},
			expectedImmediate: []bool{},
			expectedTicketIDs: []string{},
		},
		// Test cases for ! suffix
		{
			name:              "Immediate posting with ! suffix",
			message:           "Fix urgent issue URGENT-999! right away",
			expectedMatches:   []string{"URGENT-999!"},
			expectedPublic:    []bool{false},
			expectedImmediate: []bool{true},
			expectedTicketIDs: []string{"URGENT-999"},
		},
		{
			name:              "Immediate public with #TICKETID!",
			message:           "Critical fix for #CRIT-123! needs attention",
			expectedMatches:   []string{"#CRIT-123!"},
			expectedPublic:    []bool{true},
			expectedImmediate: []bool{true},
			expectedTicketIDs: []string{"CRIT-123"},
		},
		{
			name:              "Immediate public with $TICKETID!",
			message:           "Emergency patch $EMERG-456! deployed",
			expectedMatches:   []string{"$EMERG-456!"},
			expectedPublic:    []bool{true},
			expectedImmediate: []bool{true},
			expectedTicketIDs: []string{"EMERG-456"},
		},
		{
			name:              "! suffix at end of sentence",
			message:           "See ticket TASK-789!",
			expectedMatches:   []string{"TASK-789!"},
			expectedPublic:    []bool{false},
			expectedImmediate: []bool{true},
			expectedTicketIDs: []string{"TASK-789"},
		},
		{
			name:              "Mixed tickets with ! suffix and prefixes",
			message:           "Fix NORM-111, urgent BUG-222!, public #INFO-333, and critical $ALERT-444!",
			expectedMatches:   []string{"NORM-111", "BUG-222!", "#INFO-333", "$ALERT-444!"},
			expectedPublic:    []bool{false, false, true, true},
			expectedImmediate: []bool{false, true, false, true},
			expectedTicketIDs: []string{"NORM-111", "BUG-222", "INFO-333", "ALERT-444"},
		},
		{
			name:              "Combined % prefix with ! suffix",
			message:           "Super urgent %SUPER-555! fix",
			expectedMatches:   []string{"%SUPER-555!"},
			expectedPublic:    []bool{false},
			expectedImmediate: []bool{true},
			expectedTicketIDs: []string{"SUPER-555"},
		},
		{
			name:              "Triple combination: #%TICKETID!",
			message:           "Maximum urgency #%TRIPLE-666! fix",
			expectedMatches:   []string{"#%TRIPLE-666!"},
			expectedPublic:    []bool{true},
			expectedImmediate: []bool{true},
			expectedTicketIDs: []string{"TRIPLE-666"},
		},
		{
			name:              "! in middle should not match as suffix",
			message:           "Check invalid format: TICKET-123 with exclamation!",
			expectedMatches:   []string{"TICKET-123"},
			expectedPublic:    []bool{false},
			expectedImmediate: []bool{false},
			expectedTicketIDs: []string{"TICKET-123"},
		},
	}

	allTestsPassed := true

	for i, testCase := range testCases {
		fmt.Printf("Test %d: %s\n", i+1, testCase.name)
		fmt.Printf("Message: %q\n", testCase.message)

		foundTickets := jiraTicketRegex.FindAllStringSubmatch(testCase.message, -1)
		fmt.Printf("Raw matches: %v\n", foundTickets)

		// Process matches like the main application does
		actualMatches := []string{}
		actualPublic := []bool{}
		actualImmediate := []bool{}
		actualTicketIDs := []string{}

		if len(foundTickets) > 0 {
			for _, match := range foundTickets {
				if len(match) > 2 {
					rawTicketID := match[2]
					actualMatches = append(actualMatches, rawTicketID)

					var ticketID string
					var forcePublic bool
					var forceImmediate bool

					// Parse prefixes: $, #, % and combinations, plus ! suffix (same as main.go)
					prefixes := ""
					actualTicket := rawTicketID
					hasSuffix := false

					// Extract all leading prefix characters
					for len(actualTicket) > 0 && (actualTicket[0] == '$' || actualTicket[0] == '#' || actualTicket[0] == '%') {
						prefixes += string(actualTicket[0])
						actualTicket = actualTicket[1:]
					}

					// Check for ! suffix
					if len(actualTicket) > 0 && actualTicket[len(actualTicket)-1] == '!' {
						hasSuffix = true
						actualTicket = actualTicket[:len(actualTicket)-1] // Remove ! from end
					}

					ticketID = actualTicket

					// Determine flags based on prefixes and suffix
					forcePublic = strings.Contains(prefixes, "$") || strings.Contains(prefixes, "#")
					forceImmediate = strings.Contains(prefixes, "%") || hasSuffix

					actualPublic = append(actualPublic, forcePublic)
					actualImmediate = append(actualImmediate, forceImmediate)
					actualTicketIDs = append(actualTicketIDs, ticketID)
				}
			}
		}

		// Compare results
		testPassed := true

		if !slicesEqual(actualMatches, testCase.expectedMatches) {
			fmt.Printf("❌ FAIL: Expected matches %v, got %v\n", testCase.expectedMatches, actualMatches)
			testPassed = false
		}

		if !boolSlicesEqual(actualPublic, testCase.expectedPublic) {
			fmt.Printf("❌ FAIL: Expected public flags %v, got %v\n", testCase.expectedPublic, actualPublic)
			testPassed = false
		}

		if !boolSlicesEqual(actualImmediate, testCase.expectedImmediate) {
			fmt.Printf("❌ FAIL: Expected immediate flags %v, got %v\n", testCase.expectedImmediate, actualImmediate)
			testPassed = false
		}

		if !slicesEqual(actualTicketIDs, testCase.expectedTicketIDs) {
			fmt.Printf("❌ FAIL: Expected ticket IDs %v, got %v\n", testCase.expectedTicketIDs, actualTicketIDs)
			testPassed = false
		}

		if testPassed {
			fmt.Printf("✅ PASS\n")
		} else {
			allTestsPassed = false
		}

		// Show processed results
		for j, ticketID := range actualTicketIDs {
			publicStr := "private"
			if actualPublic[j] {
				publicStr = "PUBLIC"
			}
			immediateStr := "buffered"
			if actualImmediate[j] {
				immediateStr = "IMMEDIATE"
			}
			fmt.Printf("  -> Ticket: %s (%s, %s)\n", ticketID, publicStr, immediateStr)
		}

		fmt.Println()
	}

	if allTestsPassed {
		fmt.Println("🎉 All tests passed!")
	} else {
		fmt.Println("❌ Some tests failed!")
	}
}

// Helper functions
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func boolSlicesEqual(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
