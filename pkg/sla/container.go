package sla

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

const (
	HeaderMagic      = "sla"
	FormatVersion    = 4
	XMLFormatVersion = 3
)

// Container is the decoded `.sla` input: packed v4 files expose the decompressed payload,
// while XML v3 files preserve the original XML document as the payload.
type Container struct {
	Version byte
	Payload []byte
}

func IsHeader(header []byte) bool {
	return len(header) == 4 && string(header[:3]) == HeaderMagic && header[3] == FormatVersion
}

func Read(r io.Reader) (*Container, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read sla stream: %w", err)
	}

	if isXMLPayload(data) {
		root, err := parseXMLRootElement(data)
		if err != nil {
			return nil, err
		}
		version, err := requiredIntAttr(root.Attrs, attrVersion)
		if err != nil {
			return nil, fmt.Errorf("read xml sleigh version: %w", err)
		}
		if version != XMLFormatVersion {
			return nil, fmt.Errorf("unsupported xml sleigh version: got %d want %d", version, XMLFormatVersion)
		}
		return &Container{Version: byte(version), Payload: data}, nil
	}

	if len(data) < 4 {
		return nil, fmt.Errorf("read sla header: %w", io.ErrUnexpectedEOF)
	}
	header := data[:4]
	if string(header[:3]) != HeaderMagic {
		return nil, fmt.Errorf("invalid sla magic")
	}
	if header[3] != FormatVersion {
		return nil, fmt.Errorf("unsupported sla version: got %d want %d", header[3], FormatVersion)
	}

	zr, err := zlib.NewReader(bytes.NewReader(data[4:]))
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
