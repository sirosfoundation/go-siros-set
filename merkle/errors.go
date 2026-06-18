package merkle

import "errors"

var (
	ErrIndexOutOfRange = errors.New("merkle: index out of range")
	ErrInvalidTreeSize = errors.New("merkle: invalid tree size")
)
