package api

import (
	"errors"
	"sync"

	"github.com/0xrawsec/sod"
)

// AdminAPIUser structure definition
type AdminAPIUser struct {
	sod.Item
	Uuid        string `json:"uuid"`
	Identifier  string `json:"identifier"`
	Key         string `json:"key,omitempty"`
	Group       string `json:"group"`
	Description string `json:"description"`
}

type Users struct {
	sync.RWMutex
	uuids       map[string]*AdminAPIUser
	identifiers map[string]*AdminAPIUser
	keys        map[string]*AdminAPIUser
}

func NewUsers() *Users {
	return &Users{
		uuids:       make(map[string]*AdminAPIUser),
		identifiers: make(map[string]*AdminAPIUser),
		keys:        make(map[string]*AdminAPIUser),
	}
}

func (u *Users) Add(user *AdminAPIUser) (err error) {
	u.Lock()
	defer u.Unlock()
	if ok, msg := u.exist(user); !ok {
		u.uuids[user.Uuid] = user
		u.identifiers[user.Identifier] = user
		u.keys[user.Key] = user
	} else {
		err = errors.New(msg)
	}
	return
}

func (u *Users) Len() int {
	u.RLock()
	defer u.RUnlock()
	return len(u.uuids)

}

func (u *Users) List() (s []*AdminAPIUser) {
	u.RLock()
	defer u.RUnlock()
	s = make([]*AdminAPIUser, 0, u.Len())
	for _, v := range u.uuids {
		s = append(s, v)
	}
	return
}

func (u *Users) GetByIdentifier(identifier string) (user *AdminAPIUser, ok bool) {
	u.RLock()
	defer u.RUnlock()
	user, ok = u.identifiers[identifier]
	return
}

func (u *Users) GetByKey(key string) (user *AdminAPIUser, ok bool) {
	u.RLock()
	defer u.RUnlock()
	user, ok = u.keys[key]
	return
}

func (u *Users) GetByUUID(uuid string) (user *AdminAPIUser, ok bool) {
	u.RLock()
	defer u.RUnlock()
	user, ok = u.uuids[uuid]
	return
}

func (u *Users) exist(user *AdminAPIUser) (ok bool, message string) {
	if _, ok = u.uuids[user.Uuid]; ok {
		message = "A user with such an UUID already exists"
		return
	}
	if _, ok = u.identifiers[user.Identifier]; ok {
		message = "A user with such an identifier already exists"
		return
	}
	if _, ok = u.keys[user.Key]; ok {
		message = "A user with such a key already exists"
		return
	}
	return
}

func (u *Users) Exist(user *AdminAPIUser) (ok bool, message string) {
	u.RLock()
	defer u.RUnlock()
	return u.exist(user)
}

func (u *Users) Delete(user *AdminAPIUser) {
	u.Lock()
	defer u.Unlock()
	delete(u.uuids, user.Uuid)
	delete(u.identifiers, user.Identifier)
	delete(u.keys, user.Key)
}
