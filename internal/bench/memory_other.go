//go:build !windows

package bench

func startPeakRSSSampling() func() *float64 { return func() *float64 { return nil } }
