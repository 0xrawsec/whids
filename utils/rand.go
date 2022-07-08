package utils

import (
	"math/rand"

	"github.com/google/uuid"
)

// UnsafeUUIDGen generates a random UUID
func UnsafeUUIDGen() uuid.UUID {
	uuid := uuid.UUID{}
	for i := 0; i < len(uuid); i++ {
		uuid[i] = uint8(rand.Uint32() >> 24)
	}
	return uuid
}

// UnsafeKeyGen is an API key generator, supposed to generate an [[:alnum:]] key
func UnsafeKeyGen(size int) string {
	key := make([]byte, 0, size)
	for len(key) < size {
		b := uint8(rand.Uint32() >> 24)
		switch {
		case b > 47 && b < 58:
			// 0 to 9
			key = append(key, b)
		case b > 65 && b < 90:
			// A to Z
			key = append(key, b)
		case b > 96 && b < 123:
			// a to z
			key = append(key, b)
		}
	}
	return string(key)
}
