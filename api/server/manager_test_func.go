package server

import "github.com/0xrawsec/whids/tools"

/*
Commodity functions used to configure manager from tests
without having to use HTTP API
*/

func (m *Manager) TestAddTool(t *tools.Tool) error {
	return m.db.InsertOrUpdate(t)
}
