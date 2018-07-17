package ipp

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/zmap/zgrab2/lib/http"
)

func TestStoreBody(t *testing.T) {

}

func TestBufferFromBody(t *testing.T) {
	var scanner *Scanner
	scanner = &Scanner{}
	scanner.config = &Flags{}
	// Truncation occurs at 1024 bytes b/c MaxSize == 1
	scanner.config.MaxSize = 1
	maxLength := scanner.config.MaxSize * 1024

	resp := new(http.Response)
	empty := []byte{}
	nonTruncated := []byte("a")
	truncated := bytes.Repeat([]byte("a"), maxLength + 1)

	type Test struct {
		resp *http.Response
		bytes []byte
		contentLength int
		expected []byte
	}

	// ContentLength == -1 indicates unknown length, so bufferFromBody will copy up to MaxSize KB
	tables := []Test {
		// Empty
		{resp, empty, -1, empty},
		{resp, empty, len(empty), empty},
		// Non-truncated
		{resp, nonTruncated, -1, nonTruncated},
		{resp, nonTruncated, len(nonTruncated), nonTruncated},
		// Truncated
		{resp, truncated, -1, truncated[:maxLength]},
		{resp, truncated, len(truncated), truncated[:maxLength]},
		// Nil response
		// Should result in empty buffer
		{nil, truncated, -1, empty},
		{nil, truncated, len(truncated), empty},
	}
	for i, table := range tables {
		if table.resp != nil {
			table.resp.ContentLength = int64(table.contentLength)
			table.resp.Body = ioutil.NopCloser(bytes.NewBuffer(table.bytes))
		}
		buf := bufferFromBody(table.resp, scanner)
		if !bytes.Equal(buf.Bytes(), table.expected) {
			t.Errorf("Incorrect output for input %d. wanted: %v, got: %v", i, table.expected, buf.Bytes())
		}
		// Tests executing a second time to ensure that bufferFromBody is properly
		// re-populating resp.Body for subsequent calls to bufferFromBody
		buf = bufferFromBody(table.resp, scanner)
		if !bytes.Equal(buf.Bytes(), table.expected) {
			t.Errorf("Can't execute twice on input %d.", i)
		}
	}
}

func TestShouldReturnAttrs(t *testing.T) {

}

func TestDetectReadBodyError(t *testing.T) {

}

func TestReadAllAttributes(t *testing.T) {
	var scanner Scanner
	scanner.config = &Flags{}
	// Makes truncation occur at a manageable 1024 bytes, which can be reached by just copy-paste
	scanner.config.MaxSize = 1

	// Should have 3 attributes and no error. Simple well-formed example response to feed into readAllAttributes.
	body := []byte{2, 1, 4, 6, 0, 0, 0, 1, 1, 71, 0, 18, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 99, 104, 97, 114, 115, 101, 116, 0, 5, 117, 116, 102, 45, 56, 72, 0, 27, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 110, 97, 116, 117, 114, 97, 108, 45, 108, 97, 110, 103, 117, 97, 103, 101, 0, 5, 101, 110, 45, 117, 115, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 3}
	if attrs, err := readAllAttributes(body, &scanner); len(attrs) != 3 || err != nil {
		t.Error()
	}

	// Should have no attributes and a "Reported field length runs out of bounds." error
	tooLongName := []byte{2, 1, 4, 6, 0, 0, 0, 1, 1, 71, 0, 180, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 99, 104, 97, 114, 115, 101, 116, 0, 5, 117, 116, 102, 45, 56, 72, 0, 27, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 110, 97, 116, 117, 114, 97, 108, 45, 108, 97, 110, 103, 117, 97, 103, 101, 0, 5, 101, 110, 45, 117, 115, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 3}
	if attrs, err := readAllAttributes(tooLongName, &scanner);
		len(attrs) != 0 || err.Error() != ErrInvalidLength.Error() {
		t.Error()
	}

	// Should have one attribute with no values and "attributes-charset" as its name; and a "Reported field length..." error
	tooLongValue := []byte{2, 1, 4, 6, 0, 0, 0, 1, 1, 71, 0, 18, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 99, 104, 97, 114, 115, 101, 116, 0, 150, 117, 116, 102, 45, 56, 72, 0, 27, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 110, 97, 116, 117, 114, 97, 108, 45, 108, 97, 110, 103, 117, 97, 103, 101, 0, 5, 101, 110, 45, 117, 115, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 3}
	if attrs, err := readAllAttributes(tooLongValue, &scanner);
		len(attrs) != 1 || len(attrs[0].Values) != 0 || attrs[0].Name != "attributes-charset" || err.Error() != ErrInvalidLength.Error() {
		t.Error()
	}

	// Should have no error, since all 19 attributes can be read. It's a final value of length 50.
	fullLength := []byte{2, 1, 4, 6, 0, 0, 0, 1, 1, 71, 0, 18, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 99, 104, 97, 114, 115, 101, 116, 0, 5, 117, 116, 102, 45, 56, 72, 0, 27, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 110, 97, 116, 117, 114, 97, 108, 45, 108, 97, 110, 103, 117, 97, 103, 101, 0, 5, 101, 110, 45, 117, 115, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 50, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 3}
	if attrs, err := readAllAttributes(fullLength, &scanner);
		len(attrs) != 19 || len(attrs[18].Values[0].Bytes) != 50 || err != nil {
		t.Error()
	}

	// Should have no error, even though only 19 or 20 attributes can be read. The name of a new value is incompletely read, but then discarded without error, since truncation is detected.
	truncated := []byte{2, 1, 4, 6, 0, 0, 0, 1, 1, 71, 0, 18, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 99, 104, 97, 114, 115, 101, 116, 0, 5, 117, 116, 102, 45, 56, 72, 0, 27, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 110, 97, 116, 117, 114, 97, 108, 45, 108, 97, 110, 103, 117, 97, 103, 101, 0, 5, 101, 110, 45, 117, 115, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97}
	if attrs, err := readAllAttributes(truncated, &scanner);
		len(attrs) != 19 || len(attrs[18].Values[0].Bytes) != 36 || err != nil {
		t.Error()
	}

	// Should have no attributes and no error.
	noGroups := []byte{2, 1, 4, 6, 0, 0, 0, 1, 3}
	if attrs, err := readAllAttributes(noGroups, &scanner); len(attrs) != 0 || err != nil {
		t.Error()
	}

	// Should have usual 3 attributes and no error.
	emptyGroups := []byte{2, 1, 4, 6, 0, 0, 0, 1, 1, 71, 0, 18, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 99, 104, 97, 114, 115, 101, 116, 0, 5, 117, 116, 102, 45, 56, 72, 0, 27, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 110, 97, 116, 117, 114, 97, 108, 45, 108, 97, 110, 103, 117, 97, 103, 101, 0, 5, 101, 110, 45, 117, 115, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 0, 1, 2, 4, 5, 3}
	if attrs, err := readAllAttributes(emptyGroups, &scanner); len(attrs) != 3 || err != nil {
		t.Error()
	}

	// Should heave no attribute and no error.
	dataAfterEndOfAttrs := []byte{2, 1, 4, 6, 0, 0, 0, 1, 3, 1, 71, 0, 18, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 99, 104, 97, 114, 115, 101, 116, 0, 5, 117, 116, 102, 45, 56, 72, 0, 27, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 110, 97, 116, 117, 114, 97, 108, 45, 108, 97, 110, 103, 117, 97, 103, 101, 0, 5, 101, 110, 45, 117, 115, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 3}
	if attrs, err := readAllAttributes(dataAfterEndOfAttrs, &scanner); len(attrs) != 0 || err != nil {
		t.Error()
	}

	// We're never expecting to read 0 bytes unless it's into a 0-byte field, so io.EOF means something went wrong.
	// Should have 0 attributes and "Fewer body bytes read than expected." error, because we expected to read at least one delimiter-tag.
	noTagToRead := []byte{2, 1, 4, 6, 0, 0, 0, 1}
	if attrs, err := readAllAttributes(noTagToRead, &scanner); len(attrs) != 0 || err.Error() != ErrBodyTooShort.Error() {
		t.Error()
	}

	// We're never expecting to read some but not all bytes and then hit io.ErrUnexpectedEOF, so that would indicate an issue (one case is too-short body).
	tooShortBody := []byte{2, 1, 4, 6}
	if attrs, err := readAllAttributes(tooShortBody, &scanner); len(attrs) != 0 || err.Error() != ErrBodyTooShort.Error() {
		t.Error()
	}

	//things that should actually make this fail:
	//just blatantly not IPP: probably fail with wrong field-length error or reported field length error eventually?
}

// FIXME: Unclear if these tests would differ from readAllAttributes in any meaningful way
func TestTryReadAttributes(t *testing.T) {

}

func TestVersionNotSupported(t *testing.T) {
	// Content other than 3rd and 4th bytes is just filler, since they are ignored while reading
	// Empty response
	empty := ""
	// Response too short to read any status code
	tooShort := "abc"
	// Long enough response w/ status code of 0x0503 (meaning server-error-version-not-supported)
	badCode := "ab\x05\x03"
	// Long enough response w/ another status code
	goodCode := "ab\x04\x06"
	// A full example response w/o server-error-version-not-supported
	actual := string([]byte{2, 1, 4, 6, 0, 0, 0, 1, 1, 71, 0, 18, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 99, 104, 97, 114, 115, 101, 116, 0, 5, 117, 116, 102, 45, 56, 72, 0, 27, 97, 116, 116, 114, 105, 98, 117, 116, 101, 115, 45, 110, 97, 116, 117, 114, 97, 108, 45, 108, 97, 110, 103, 117, 97, 103, 101, 0, 5, 101, 110, 45, 117, 115, 65, 0, 14, 115, 116, 97, 116, 117, 115, 45, 109, 101, 115, 115, 97, 103, 101, 0, 36, 84, 104, 101, 32, 112, 114, 105, 110, 116, 101, 114, 32, 111, 114, 32, 99, 108, 97, 115, 115, 32, 100, 111, 101, 115, 32, 110, 111, 116, 32, 101, 120, 105, 115, 116, 46, 3})

	type Test struct {
		body string
		result bool
	}

	tables := []Test {
		{empty, false},
		{tooShort, false},
		{badCode, true},
		{goodCode, false},
		{actual, false},
	}

	for i, table := range tables {
		if result := versionNotSupported(table.body); result != table.result {
			t.Errorf("Test case %d failed. wanted: %t, got: %t", i, table.result, result)
		}
	}
}

func TestAugmentWithCUPSData(t *testing.T) {

}

func TestSendIPPRequest(t *testing.T) {

}

func TestHasContentType(t *testing.T) {
	type Test struct {
		cType string
		expected bool
	}

	tables := []Test{
		//Fully wrong
		{"text/html", false},
		//Correct type, wrong subtype
		{"application/pdf", false},
		//Wrong type, correct subtype
		{"text/ipp", false},
		//Followed by comma like Virata-EmWeb
		{"application/ipp, public", true},
		//Followed by comma in a different manner
		{"application/ipp, extra", true},
		//Correct type & subtype
		{"application/ipp", true},
		//Correct type & subtype with parameter
		{"application/ipp; parameter=value", true},
		//Only subtype
		{"ipp", true},
		//Only subtype, but capitalized like Rapid Logic
		{"IPP", true},
	}

	resp := new(http.Response)
	resp.Header = make(http.Header)

	for i, table := range tables {
		resp.Header.Set("Content-Type", table.cType)
		if result := hasContentType(resp, ContentType); result != table.expected {
			t.Errorf("Test case %d failed. wanted: %t, got: %t", i, table.expected, result)
		}
	}
}

func TestIsIPP(t *testing.T) {

}

// FIXME: Unclear how to test this instead of lower-down functions
func TestGrab(t *testing.T) {

}

func TestRedirectsToLocalhost(t *testing.T) {
	// example with localhost domain
	// example with 127.0.0.1 ip
	// example with any other redirect
}

// FIXME: Can functions which return functions really be tested? Maybe by testing their result?
// func TestGetCheckRedirect
// func TestGetTLSDialer

func TestGetHTTPURL(t *testing.T) {

}

func TestNewIPPScan(t *testing.T) {

}

func TestCleanup(t *testing.T) {

}

func TestTryGrabForVersions(t *testing.T) {

}

func TestShouldReportResult(t *testing.T) {

}

// FIXME: Unclear how to test this instead of lower-level functions
func TestScan(t *testing.T) {

}