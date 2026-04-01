package sla

import (
	"bytes"
	"testing"
)

func TestEncodeReadRoundTrip(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	encoded, err := Encode(payload)
	if err != nil {
		t.Fatalf("Encode() returned unexpected error: %v", err)
	}
	if !IsHeader(encoded[:4]) {
		t.Fatal("encoded container did not start with valid sla header")
	}

	container, err := Read(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("Read() returned unexpected error: %v", err)
	}
	if container.Version != FormatVersion {
		t.Fatalf("unexpected version: got %d want %d", container.Version, FormatVersion)
	}
	if !bytes.Equal(container.Payload, payload) {
		t.Fatalf("unexpected payload: got %v want %v", container.Payload, payload)
	}
}

func TestReadRejectsBadMagic(t *testing.T) {
	bad := []byte{'b', 'a', 'd', FormatVersion}
	_, err := Read(bytes.NewReader(bad))
	if err == nil {
		t.Fatal("Read() returned nil for bad magic")
	}
}

func TestReadRejectsBadVersion(t *testing.T) {
	bad := []byte{'s', 'l', 'a', 0x7f}
	_, err := Read(bytes.NewReader(bad))
	if err == nil {
		t.Fatal("Read() returned nil for bad version")
	}
}

func TestReadRejectsBrokenPayload(t *testing.T) {
	bad := []byte{'s', 'l', 'a', FormatVersion, 0x00, 0x01, 0x02}
	_, err := Read(bytes.NewReader(bad))
	if err == nil {
		t.Fatal("Read() returned nil for broken compressed payload")
	}
}
