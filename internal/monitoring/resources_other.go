//go:build !linux

package monitoring

func readResources() resourceReading { return resourceReading{} }
