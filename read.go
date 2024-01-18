package pefile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
)

// Unless told otherwise, never try an read a string longer than 2<<20 from a PE header.
const maxStringLength = 2 << 20

// readRVA does a binary.Read() at the given RVA by attempting to translate
// it to a file offset first
func (pe *PEFile) readRVA(iface interface{}, rva uint32) error {
	offset, err := pe.getOffsetFromRva(rva)
	if err != nil {
		return err
	}
	return pe.readOffset(iface, offset)
}

// readOffset does a binary.Read() from the file offset given
func (pe *PEFile) readOffset(iface interface{}, offset uint32) error {
	size := uint32(binary.Size(iface))
	if offset+size < offset {
		return fmt.Errorf("overflow, was -1 passed to parseHeader: %s:%x, offset 0x%x, file length: 0x%x", reflect.TypeOf(iface), size, offset, pe.dataLen)
	}
	if offset+size > pe.dataLen {
		return fmt.Errorf("requested header %s:%x would read past end of the file, offset 0x%x, file length: 0x%x", reflect.TypeOf(iface), size, offset, pe.dataLen)
	}

	raw := make([]byte, size)
	if _, err := pe.readerAt.ReadAt(raw, int64(offset)); err != nil {
		return err
	}
	return binary.Read(bytes.NewReader(raw), binary.LittleEndian, iface)
}

// Get an ASCII string from within the data at an RVA considering
// section
func (pe *PEFile) readStringRVA(rva uint32, maxLen uint32) ([]byte, error) {
	start, length, err := pe.getDataBounds(rva)
	if err != nil {
		return nil, err
	}

	if length > maxLen {
		length = maxLen
	}

	return pe.readStringOffset(start, length)
}

// Get an ASCII string from within the data.
func (pe *PEFile) readStringOffset(offset uint32, maxLen uint32) ([]byte, error) {
	if offset > pe.dataLen {
		return nil, fmt.Errorf("Attempted to read ASCII string past end of file at offset: 0x%x", offset)
	}

	// if offset+maxLen is too large, cap it reasonably.
	// This allows the ReadAt method call below to be
	// comfortable with io.ReaderAt's EOF error semantics.
	if offset+maxLen > pe.dataLen {
		maxLen = pe.dataLen - offset
	}

	const chunkSize = 3

	var result []byte
	buf := make([]byte, chunkSize)

	for totalRead := uint32(0); totalRead < maxLen; {
		// Determine the size of the next chunk to read
		remaining := maxLen - totalRead
		if remaining > chunkSize {
			remaining = chunkSize
		}

		// Read data into the buffer
		n, err := pe.readerAt.ReadAt(buf[:remaining], int64(offset+totalRead))
		if err != nil && err != io.EOF {
			return nil, err
		}
		fmt.Println("Chunked read at read: ", n, "bytes => ", string(buf[:n]))

		// Append the read bytes to the result, and check for null terminator
		for i := 0; i < n; i++ {
			if buf[i] == 0 {
				result = append(result, buf[:i]...)
				fmt.Println("returning string:", string(result))
				return result, nil
			}
			result = append(result, buf[i])
		}

		// Update total read bytes and continue if more data is expected
		totalRead += uint32(n)
		if uint32(n) < remaining || err == io.EOF {
			break
		}
	}

	return result, nil
}
