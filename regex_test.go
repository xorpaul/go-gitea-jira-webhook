package main

import (
	"regexp"
	"strings"
	"testing"
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

// Helper functions for testing
func extractTicketInfo(match string) (ticketID string, isPublic, isImmediate bool) {
	// Remove leading/trailing whitespace and extract the ticket ID with prefixes
	ticketMatch := strings.TrimSpace(match)

	// Check for immediate posting indicators
	isImmediate = strings.Contains(ticketMatch, "%") || strings.HasSuffix(ticketMatch, "!")

	// Check for public visibility indicators
	isPublic = strings.Contains(ticketMatch, "$") || strings.Contains(ticketMatch, "#")

	// Extract clean ticket ID (remove prefixes and suffix)
	ticketID = ticketMatch
	// Remove prefixes
	ticketID = strings.TrimLeft(ticketID, "$#%")
	// Remove ! suffix if present
	ticketID = strings.TrimSuffix(ticketID, "!")

	return ticketID, isPublic, isImmediate
}

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

func TestJiraTicketRegex(t *testing.T) {
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

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			matches := jiraTicketRegex.FindAllStringSubmatch(testCase.message, -1)

			// Extract the actual matches from capture group 2
			var actualMatches []string
			var actualPublic []bool
			var actualImmediate []bool
			var actualTicketIDs []string

			for _, match := range matches {
				if len(match) >= 3 {
					ticketMatch := match[2] // The ticket ID with prefixes from capture group 2
					actualMatches = append(actualMatches, ticketMatch)

					// Extract ticket info
					ticketID, isPublic, isImmediate := extractTicketInfo(ticketMatch)
					actualTicketIDs = append(actualTicketIDs, ticketID)
					actualPublic = append(actualPublic, isPublic)
					actualImmediate = append(actualImmediate, isImmediate)
				}
			}

			// Check matches
			if !slicesEqual(actualMatches, testCase.expectedMatches) {
				t.Errorf("Matches mismatch.\nExpected: %v\nActual: %v", testCase.expectedMatches, actualMatches)
			}

			// Check public visibility
			if !boolSlicesEqual(actualPublic, testCase.expectedPublic) {
				t.Errorf("Public visibility mismatch.\nExpected: %v\nActual: %v", testCase.expectedPublic, actualPublic)
			}

			// Check immediate posting
			if !boolSlicesEqual(actualImmediate, testCase.expectedImmediate) {
				t.Errorf("Immediate posting mismatch.\nExpected: %v\nActual: %v", testCase.expectedImmediate, actualImmediate)
			}

			// Check ticket IDs
			if !slicesEqual(actualTicketIDs, testCase.expectedTicketIDs) {
				t.Errorf("Ticket IDs mismatch.\nExpected: %v\nActual: %v", testCase.expectedTicketIDs, actualTicketIDs)
			}
		})
	}
}

func TestJiraTicketRegexBenchmark(t *testing.T) {
	jiraTicketRegex := regexp.MustCompile(`(^|[^A-Za-z0-9-!])([\$#%]*[A-Z]+-[0-9]+!?)(?:[^A-Za-z0-9-!]|$)`)

	testMessage := "Fix bugs for #PROJ-123 and $TASK-456, %URGENT-999 and #%CRIT-111"

	b := testing.B{}
	b.ResetTimer()
	for i := 0; i < 1000; i++ {
		matches := jiraTicketRegex.FindAllStringSubmatch(testMessage, -1)
		if len(matches) != 4 {
			t.Errorf("Expected 4 matches, got %d", len(matches))
		}
	}
}
