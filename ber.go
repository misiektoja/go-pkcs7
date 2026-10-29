package pkcs7

import (
	"bytes"
	"errors"
)

// maxBERDepth bounds the nesting of constructed elements. CMS messages nest about a dozen levels
// deep, so the bound only stops hostile input from driving the recursion.
const maxBERDepth = 64

// maxLengthOctets limits a long-form length to four octets, which keeps every length within int32.
const maxLengthOctets = 4

// endOfContents is the octet pair that closes an indefinite-length element.
var endOfContents = []byte{0x00, 0x00}

// ber2der converts one BER encoded element into DER by giving every element a definite, minimal
// length. It keeps the order of SET members and the form of constructed strings, so the result is
// DER only for input that already followed the other DER rules. Bytes after the element are an
// error.
func ber2der(ber []byte) ([]byte, error) {
	if len(ber) == 0 {
		return nil, errors.New("ber2der: input ber is empty")
	}
	out, rest, err := convertElement(make([]byte, 0, len(ber)), ber, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("ber2der: trailing data after the element")
	}
	return out, nil
}

// convertElement appends the DER form of the element at the start of in to out and returns the
// input that follows it.
func convertElement(out, in []byte, depth int) ([]byte, []byte, error) {
	if depth >= maxBERDepth {
		return nil, nil, errors.New("ber2der: elements nested too deeply")
	}
	tagLen, err := identifierLength(in)
	if err != nil {
		return nil, nil, err
	}
	// Universal tag number 0 is reserved for end-of-contents octets, which only close an
	// indefinite-length element. Anywhere else it is malformed, and converting it could turn a
	// non-minimal encoding into a stray terminator.
	if in[0]&^0x20 == 0x00 {
		return nil, nil, errors.New("ber2der: unexpected end-of-contents octets or reserved universal tag 0")
	}
	constructed := in[0]&0x20 != 0
	length, indefinite, headerLen, err := readLength(in, tagLen)
	if err != nil {
		return nil, nil, err
	}
	tag := in[:tagLen]
	body := in[headerLen:]

	if !indefinite {
		if length > len(body) {
			return nil, nil, errors.New("ber2der: BER tag length is more than available data")
		}
		content, rest := body[:length], body[length:]
		if !constructed {
			out = append(out, tag...)
			out = appendLength(out, len(content))
			return append(out, content...), rest, nil
		}
		inner, err := convertChildren(content, depth)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, tag...)
		out = appendLength(out, len(inner))
		return append(out, inner...), rest, nil
	}

	if !constructed {
		return nil, nil, errors.New("ber2der: indefinite length requires constructed encoding")
	}
	inner, rest, err := convertIndefiniteChildren(body, depth)
	if err != nil {
		return nil, nil, err
	}
	out = append(out, tag...)
	out = appendLength(out, len(inner))
	return append(out, inner...), rest, nil
}

// convertChildren converts the children of a definite-length constructed element. Every child must
// end inside content and the children must fill it exactly.
func convertChildren(content []byte, depth int) ([]byte, error) {
	var inner []byte
	for len(content) > 0 {
		var err error
		inner, content, err = convertElement(inner, content, depth+1)
		if err != nil {
			return nil, err
		}
	}
	return inner, nil
}

// convertIndefiniteChildren converts the children of an indefinite-length element up to its
// end-of-contents octets and returns the input after them.
func convertIndefiniteChildren(body []byte, depth int) ([]byte, []byte, error) {
	inner := []byte{}
	for {
		if len(body) < len(endOfContents) {
			return nil, nil, errors.New("ber2der: cannot move offset forward, end of ber data reached")
		}
		if bytes.HasPrefix(body, endOfContents) {
			return inner, body[len(endOfContents):], nil
		}
		var err error
		inner, body, err = convertElement(inner, body, depth+1)
		if err != nil {
			return nil, nil, err
		}
	}
}

// identifierLength returns the number of identifier octets at the start of in. It requires at least
// one octet after them for the length.
func identifierLength(in []byte) (int, error) {
	if len(in) < 2 {
		return 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
	}
	if in[0]&0x1F != 0x1F {
		return 1, nil
	}
	// High tag number form: base-128 octets, the last one without the continuation bit.
	for i := 1; i < len(in); i++ {
		if in[i]&0x80 == 0 {
			if i+1 >= len(in) {
				return 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
			}
			return i + 1, nil
		}
		if i > 4 {
			return 0, errors.New("ber2der: BER tag number too long")
		}
	}
	return 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
}

// readLength decodes the length octets that follow the identifier. It returns the content length,
// whether the length is indefinite and the total header length.
func readLength(in []byte, offset int) (length int, indefinite bool, headerLen int, err error) {
	l := in[offset]
	offset++
	switch {
	case l < 0x80:
		return int(l), false, offset, nil
	case l == 0x80:
		return 0, true, offset, nil
	case l == 0xFF:
		return 0, false, 0, errors.New("ber2der: reserved BER length octet")
	}
	n := int(l & 0x7F)
	if n > maxLengthOctets {
		return 0, false, 0, errors.New("ber2der: BER tag length too long")
	}
	if n > len(in)-offset {
		return 0, false, 0, errors.New("ber2der: BER tag length is more than available data")
	}
	if n == maxLengthOctets && in[offset] > 0x7F {
		return 0, false, 0, errors.New("ber2der: BER tag length is negative")
	}
	// BER allows leading zero octets in a long-form length. They are dropped when the length is
	// written again.
	for _, b := range in[offset : offset+n] {
		length = length<<8 | int(b)
	}
	return length, false, offset + n, nil
}

// appendLength appends the minimal DER encoding of length.
func appendLength(out []byte, length int) []byte {
	if length < 0x80 {
		return append(out, byte(length)) //nolint:gosec // length is below 0x80.
	}
	n := 0
	for v := length; v > 0; v >>= 8 {
		n++
	}
	out = append(out, 0x80|byte(n)) //nolint:gosec // n counts the octets of an int, at most 8.
	for i := n - 1; i >= 0; i-- {
		out = append(out, byte(length>>(8*i))) //nolint:gosec // Each octet is truncated on purpose.
	}
	return out
}
