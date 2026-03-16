// Package testutil provides shared test helper functions for the checks package.
package testutil

// BoolPtr returns a pointer to the provided bool value.
// This is useful for creating pointers to bool literals in test cases.
func BoolPtr(b bool) *bool { return &b }

// Int32Ptr returns a pointer to the provided int32 value.
// This is useful for creating pointers to int32 literals in test cases.
func Int32Ptr(i int32) *int32 { return &i }

// Int64Ptr returns a pointer to the provided int64 value.
// This is useful for creating pointers to int64 literals in test cases.
func Int64Ptr(i int64) *int64 { return &i }
