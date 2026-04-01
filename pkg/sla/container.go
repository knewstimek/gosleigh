package sla

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

const (
	HeaderMagic   = "sla"
	FormatVersion = 4
)

// Container is the outer `.sla` container: a fixed 4-byte header plus a zlib-compressed payload.
type Container struct {
	Version byte
	Payload []byte
}

func IsHeader(header []byte) bool {
	return len(header) == 4 && string(header[:3]) == HeaderMagic && header[3] == FormatVersion
}

func Read(r io.Reader) (*Container, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read sla header: %w", err)
	}
	if string(header[:3]) != HeaderMagic {
		return nil, fmt.Errorf("invalid sla magic")
	}
	if header[3] != FormatVersion {
		return nil, fmt.Errorf("unsupported sla version: got %d want %d", header[3], FormatVersion)
	}

	zr, err := zlib.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("open sla zlib stream: %w", err)
	}
	defer zr.Close()

	payload, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("read sla payload: %w", err)
	}

	return &Container{Version: header[3], Payload: payload}, nil
}

func Write(w io.Writer, payload []byte) error {
	if _, err := io.WriteString(w, HeaderMagic); err != nil {
		return fmt.Errorf("write sla magic: %w", err)
	}
	if _, err := w.Write([]byte{FormatVersion}); err != nil {
		return fmt.Errorf("write sla version: %w", err)
	}

	zw := zlib.NewWriter(w)
	if _, err := zw.Write(payload); err != nil {
		_ = zw.Close()
		return fmt.Errorf("write sla payload: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("finalize sla payload: %w", err)
	}
	return nil
}

func Encode(payload []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := Write(&buf, payload); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
