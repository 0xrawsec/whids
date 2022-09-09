package utils

import (
	"crypto/rand"
	mrand "math/rand"

	"github.com/google/uuid"
)

func randByte() (byte, error) {
	var b [1]byte
	if _, err := rand.Reader.Read(b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

// UnsafeUUID generates a random UUID
func UnsafeUUID() uuid.UUID {
	uuid := uuid.UUID{}
	for i := 0; i < len(uuid); i++ {
		uuid[i] = uint8(mrand.Uint32() >> 24)
	}
	return uuid
}

func UUIDOrPanic() (u uuid.UUID) {
	var err error

	if u, err = NewUUID(); err != nil {
		panic(err)
	}

	return
}

// UUIDGen generates a random UUID
func NewUUIDString() (string, error) {
	var u uuid.UUID
	var err error
	if u, err = NewUUID(); err != nil {
		return "", err
	}
	return u.String(), err
}

// NewUUID generates a random UUID
func NewUUID() (uuid.UUID, error) {
	return uuid.NewRandom()
}

func NewKeyOrPanic(size int) (key string) {
	var err error

	if key, err = NewKey(size); err != nil {
		panic(err)
	}

	return
}

// NewKey is an API key generator, supposed to generate an [[:alnum:]] key
func NewKey(size int) (key string, err error) {
	var b byte
	tmp := make([]byte, 0, size)
	for len(tmp) < size {
		//b := uint8(rand.Uint32() >> 24)
		if b, err = randByte(); err != nil {
			return
		}
		switch {
		case b > 47 && b < 58:
			// 0 to 9
			tmp = append(tmp, b)
		case b > 65 && b < 90:
			// A to Z
			tmp = append(tmp, b)
		case b > 96 && b < 123:
			// a to z
			tmp = append(tmp, b)
		}
	}
	key = string(tmp)
	return
}

func UUIDKeyPair(skey int) (suuid, key string, err error) {
	var u uuid.UUID

	if u, err = NewUUID(); err != nil {
		return
	}
	suuid = u.String()

	if key, err = NewKey(skey); err != nil {
		return
	}

	return
}
