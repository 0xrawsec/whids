package openapi

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

const (
	ContentTypeJson        = "application/json"
	ContentTypeXML         = "application/xml"
	ContentTypeOctetStream = "application/octet-stream"
)

type OpenAPI struct {
	OpenAPI       string                `json:"openapi,omitempty"`
	Info          *Info                 `json:"info,omitempty"`
	Servers       []*Server             `json:"servers,omitempty"`
	TestingServer *Server               `json:"-"` // there to generate tests
	Paths         map[string]*PathItem  `json:"paths,omitempty"`
	Components    Components            `json:"components,omitempty"`
	Security      []SecurityRequirement `json:"security,omitempty"`
	// Not in OpenAPI spec
	Client            *http.Client              `json:"-"`
	ApiKey            *SecurityScheme           `json:"-"`
	ValidateOperation func(i interface{}) error `json:"-"`
}

type Components struct {
	Schemas         map[string]Schema         `json:"schemas,omitempty"`
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty"`
}

type SecurityScheme struct {
	Type             string     `json:"type,omitempty"`
	Description      string     `json:"description,omitempty"`
	Name             string     `json:"name,omitempty"`
	In               string     `json:"in,omitempty"`
	Scheme           string     `json:"scheme,omitempty"`
	BearerFormat     string     `json:"bearerFormat,omitempty"`
	Flows            *OAuthFlow `json:"flows,omitempty"`
	OpenIdConnectUrl string     `json:"openIdConnect_url,omitempty"`
	// Not in OpenAPI spec but here for easier integration
	Value string `json:"-"`
}

type OAuthFlow struct {
}

func New(openapi string, info *Info, server *Server) *OpenAPI {
	oa := &OpenAPI{
		OpenAPI: openapi,
		Info:    info,
		Servers: make([]*Server, 0),
		Paths:   make(map[string]*PathItem),
		Components: Components{
			Schemas:         make(map[string]Schema),
			SecuritySchemes: make(map[string]SecurityScheme),
		},
		Security: make([]SecurityRequirement, 0),
	}
	oa.Servers = append(oa.Servers, server)
	return oa
}

func (oa *OpenAPI) AuthApiKey(header string, value string) {
	s := SecurityScheme{
		Type:  "apiKey",
		Name:  header,
		In:    "header",
		Value: value,
	}
	oa.Components.SecuritySchemes["ApiKeyAuth"] = s
	oa.ApiKey = &s
	oa.Security = append(oa.Security, SecurityRequirement{"ApiKeyAuth": []string{}})
}

func (oa *OpenAPI) ApiURL(path string) string {
	// take testing server in priority
	server := oa.TestingServer
	if server == nil {
		server = oa.FirstServer()
	}
	serverURL := strings.Trim(server.URL, "/")
	path = strings.Trim(path, "/")
	return fmt.Sprintf("%s/%s", serverURL, path)
}

func (oa *OpenAPI) FirstServer() *Server {
	if len(oa.Servers) == 0 {
		panic("OpenAPI structure needs to have at least one server configured")
	}
	return oa.Servers[0]
}

func (oa *OpenAPI) Prepare(method string, path string, data []byte, params map[string]string, headers map[string]string) *http.Request {
	body := new(bytes.Buffer)
	URL := oa.ApiURL(path)

	// preparing request body
	if data != nil {
		if len(data) > 0 {
			body.Write(data)
		}
	}

	// preparing parameters to be passed to the query
	if params != nil {
		v := url.Values{}
		for param, value := range params {
			v.Set(param, value)
		}

		if len(params) > 0 {
			URL = fmt.Sprintf("%s?%s", URL, v.Encode())
		}
	}

	req, err := http.NewRequest(method, URL, body)
	if err != nil {
		panic(err)
	}

	// Set Headers
	for f, v := range headers {
		req.Header.Add(f, v)
	}

	return req
}

func (oa *OpenAPI) docPath(path PathItem, op Operation) {
	pi := &PathItem{}

	op.Tags = []string{path.Summary}

	switch strings.ToUpper(op.Method) {
	case "GET":
		pi.Get = &op
	case "PUT":
		pi.Put = &op
	case "POST":
		pi.Post = &op
	case "DELETE":
		pi.Delete = &op
	case "OPTIONS":
		pi.Options = &op
	case "HEAD":
		pi.Head = &op
	case "PATCH":
		pi.Patch = &op
	case "TRACE":
		pi.Trace = &op
	}

	if _, ok := oa.Paths[path.Value]; ok {
		oa.Paths[path.Value].Merge(pi)
	} else {
		oa.Paths[path.Value] = pi
	}
}

func (oa *OpenAPI) do(base *PathItem, op *Operation) (err error) {
	var req *http.Request
	var resp *http.Response
	var data []byte

	body := new(bytes.Buffer)
	URL := oa.ApiURL(base.Value)

	if op.Validate == nil {
		op.Validate = oa.ValidateOperation
	}

	if op.RequestBody != nil {
		if data, err = op.RequestBody.ContentBytes(); err != nil {
			return
		}
	}

	// preparing request body
	if data != nil {
		if len(data) > 0 {
			body.Write(data)
		}
	}

	// preparing parameters to be passed to the query
	if len(op.Parameters) > 0 {
		v := url.Values{}
		for _, p := range op.Parameters {
			switch p.In {
			case "query":
				if !p.skip {
					v.Set(p.Name, p.Value)
				}
			case "path":
				URL = fmt.Sprintf("%s/%s", URL, p.Value)
				base.Value = fmt.Sprintf("%s/{%s}", base.Value, p.Name)
				if p.suffix != "" {
					URL = fmt.Sprintf("%s%s", URL, p.suffix)
					base.Value = fmt.Sprintf("%s%s", base.Value, p.suffix)
				}
			}
		}

		if len(v) > 0 {
			URL = fmt.Sprintf("%s?%s", URL, v.Encode())
		}
	}

	req, err = http.NewRequest(op.Method, URL, body)
	if err != nil {
		return
	}

	// Set authentication header
	if oa.ApiKey != nil {
		req.Header.Add(oa.ApiKey.Name, oa.ApiKey.Value)
	}

	if resp, err = oa.Client.Do(req); err != nil {
		return
	}

	if err = op.ParseResponse(resp); err != nil {
		return
	}

	return
}

// Test does exactly what Do does except that it does not document Operation
// the other difference is that this method returns any error encountered instead
// of panicing
func (oa *OpenAPI) Test(base PathItem, op Operation) error {
	return oa.do(&base, &op)
}

func (oa *OpenAPI) Do(base PathItem, op Operation) {

	if err := oa.do(&base, &op); err != nil {
		panic(err)
	}

	// Document path
	oa.docPath(base, op)
}

type Info struct {
	Title          string   `json:"title,omitempty"`
	Description    string   `json:"description,omitempty"`
	TermsOfService string   `json:"termsOfService,omitempty"`
	Contact        *Contact `json:"contact,omitempty"`
	License        *License `json:"license,omitempty"`
	Version        string   `json:"version,omitempty"`
}

func NewInfo(title, description, version string) *Info {
	return &Info{Title: title,
		Description: description,
		Version:     version}
}

type Contact struct {
	Name  string `json:"name,omitempty"`
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

type License struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type PathItem struct {
	Ref         string      `json:"$ref,omitempty"`
	Summary     string      `json:"summary,omitempty"`
	Description string      `json:"description,omitempty"`
	Get         *Operation  `json:"get,omitempty"`
	Put         *Operation  `json:"put,omitempty"`
	Post        *Operation  `json:"post,omitempty"`
	Delete      *Operation  `json:"delete,omitempty"`
	Options     *Operation  `json:"options,omitempty"`
	Head        *Operation  `json:"head,omitempty"`
	Patch       *Operation  `json:"patch,omitempty"`
	Trace       *Operation  `json:"trace,omitempty"`
	Servers     []Server    `json:"servers,omitempty"`
	Parameters  []Parameter `json:"parameters,omitempty"`
	// Not OpenAPI standard
	Value string `json:"-"`
}

func (p *PathItem) Update() {}

func (p *PathItem) Merge(other *PathItem) {
	p.Summary = other.Summary
	p.Description = other.Description

	// merging parameters
	params := make(map[string]Parameter)
	for _, param := range p.Parameters {
		params[param.Name] = param
	}
	for _, param := range other.Parameters {
		params[param.Name] = param
	}
	p.Parameters = make([]Parameter, 0, len(params))
	for _, param := range params {
		p.Parameters = append(p.Parameters, param)
	}

	// merging operations
	// Get
	if other.Get != nil {
		if p.Get == nil {
			p.Get = other.Get
		} else {
			p.Get.Merge(other.Get)
		}
	}
	// Put
	if other.Put != nil {
		if p.Put == nil {
			p.Put = other.Put
		} else {
			p.Put.Merge(other.Put)
		}
	}
	// Post
	if other.Post != nil {
		if p.Post == nil {
			p.Post = other.Post
		} else {
			p.Post.Merge(other.Post)
		}
	}
	// Delete
	if other.Delete != nil {
		if p.Delete == nil {
			p.Delete = other.Delete
		} else {
			p.Delete.Merge(other.Delete)
		}
	}
	// Options
	if other.Options != nil {
		if p.Options == nil {
			p.Options = other.Options
		} else {
			p.Options.Merge(other.Options)
		}
	}
	// Head
	if other.Head != nil {
		if p.Head == nil {
			p.Head = other.Head
		} else {
			p.Head.Merge(other.Head)
		}
	}
	// Patch
	if other.Patch != nil {
		if p.Patch == nil {
			p.Patch = other.Patch
		} else {
			p.Patch.Merge(other.Patch)
		}
	}
	// Trace
	if other.Trace != nil {
		if p.Trace == nil {
			p.Trace = other.Trace
		} else {
			p.Trace.Merge(other.Trace)
		}
	}

}

type Operation struct {
	Tags         []string     `json:"tags,omitempty"`
	Summary      string       `json:"summary,omitempty"`
	Description  string       `json:"description,omitempty"`
	ExternalDocs *ExternalDoc `json:"externalDocs,omitempty"`
	OperationId  string       `json:"operationId,omitempty"`
	Parameters   []*Parameter `json:"parameters,omitempty"`
	RequestBody  *RequestBody `json:"requestBody,omitempty"`
	Responses    Responses    `json:"responses,omitempty"`
	//Callbacks    Callback
	Deprecated bool                `json:"deprecated,omitempty"`
	Security   SecurityRequirement `json:"security,omitempty"`
	Servers    []Server            `json:"servers,omitempty"`
	// Not OpenAPI standard
	Method   string                         `json:"-"`
	Output   interface{}                    `json:"-"`
	Validate func(output interface{}) error `json:"-"`
}

func (o *Operation) softInit() {
	if o.Responses == nil {
		o.Responses = make(Responses)
	}
}

func (o *Operation) GET(params ...*Parameter) Operation {
	new := o.SetParams(params...)
	return new.SetMethod("GET")
}

func (o *Operation) DELETE(params ...*Parameter) Operation {
	new := o.SetParams(params...)
	return new.SetMethod("DELETE")
}

func (o *Operation) POST(b *RequestBody, params ...*Parameter) Operation {
	new := o.SetMethod("POST")
	if b != nil {
		new = new.SetRequestBody(b)
	}
	return new.SetParams(params...)
}

func (o *Operation) SetMethod(method string) Operation {
	new := *o
	new.Method = method
	return new
}

func (o *Operation) SetParams(params ...*Parameter) Operation {
	new := *o
	new.Parameters = append(new.Parameters, params...)
	return new
}

func (o *Operation) SetRequestBody(b *RequestBody) Operation {
	new := *o
	new.RequestBody = b
	return new
}

func (o *Operation) ParseResponse(r *http.Response) (err error) {
	var data []byte

	o.softInit()
	ct := r.Header.Get("Content-Type")

	if data, err = ioutil.ReadAll(r.Body); err != nil {
		return
	}

	switch ct {
	case ContentTypeJson:
		if err = json.Unmarshal(data, &o.Output); err != nil {
			return err
		}
	case "":
		break
	default:
		return fmt.Errorf("cannot parse Content-Type: %s", ct)
	}

	o.Responses[fmt.Sprintf("%d", r.StatusCode)] = Response{
		Description: fmt.Sprintf("HTTP %d response", r.StatusCode),
		Content: map[string]MediaType{
			ct: {
				Example: o.Output,
				//Schema:  SchemaFrom(o.Output, ct),
			},
		},
	}

	if o.Validate != nil {
		if err := o.Validate(o.Output); err != nil {
			return err
		}
	}

	return nil
}

func (o *Operation) Merge(other *Operation) {
	// merging parameters
	params := make(map[string]*Parameter)
	for _, param := range o.Parameters {
		params[param.Name] = param
	}
	for _, param := range other.Parameters {
		params[param.Name] = param
	}
	o.Parameters = make([]*Parameter, 0, len(params))
	for _, param := range params {
		o.Parameters = append(o.Parameters, param)
	}

	// merging responses

}

type Server struct {
	URL         string                    `json:"url,omitempty"`
	Description string                    `json:"description,omitempty"`
	Variables   map[string]ServerVariable `json:"variables,omitempty"`
}

type ServerVariable struct {
	Enum        []string `json:"enum,omitempty"`
	Default     string   `json:"default,omitempty"`
	Description string   `json:"description,omitempty"`
}

type Parameter struct {
	Name            string  `json:"name,omitempty"`
	In              string  `json:"in,omitempty"`
	Description     string  `json:"description,omitempty"`
	Required        bool    `json:"required"`
	Deprecated      bool    `json:"deprecated,omitempty"`
	AllowEmptyValue bool    `json:"allowEmptyValue"`
	Schema          *Schema `json:"schema,omitempty"`
	// Not OpenAPI standard
	Value  string `json:"-"`
	skip   bool
	suffix string
}

func (p *Parameter) Suffix(s string) *Parameter {
	p.suffix = fmt.Sprintf("%s%s", p.suffix, s)
	return p
}

func (p *Parameter) Skip() *Parameter {
	p.skip = true
	return p
}

func (p *Parameter) Require() *Parameter {
	p.Required = true
	return p
}

func QueryParameter(name string, value interface{}, opts ...string) *Parameter {
	desc := fmt.Sprintf("%s query parameter", name)
	if len(opts) > 0 {
		desc = opts[0]
	}
	return &Parameter{
		Description:     desc,
		Name:            name,
		Value:           fmt.Sprintf("%v", value),
		In:              "query",
		Schema:          SchemaFrom(value, ""),
		AllowEmptyValue: true,
	}
}

func PathParameter(name string, value interface{}, opts ...string) *Parameter {
	desc := fmt.Sprintf("%s path parameter", name)
	if len(opts) > 0 {
		desc = opts[0]
	}
	return &Parameter{
		Description:     desc,
		Name:            name,
		Value:           fmt.Sprintf("%v", value),
		In:              "path",
		Schema:          SchemaFrom(value, ""),
		AllowEmptyValue: false,
		Required:        true,
	}
}

type ExternalDoc struct {
}

type RequestBody struct {
	Description string               `json:"description,omitempty"`
	Content     map[string]MediaType `json:"content,omitempty"`
	Required    bool                 `json:"required,omitempty"`
}

func JsonRequestBody(desc string, data interface{}, required bool) *RequestBody {
	return MakeRequestBody(desc, ContentTypeJson, data, required)
}

func XMLRequestBody(desc string, data interface{}, required bool) *RequestBody {
	return MakeRequestBody(desc, ContentTypeXML, data, required)
}

func BinaryRequestBody(desc string, data interface{}, required bool) *RequestBody {
	return MakeRequestBody(desc, ContentTypeOctetStream, data, required)
}

func MakeRequestBody(desc, contentType string, data interface{}, required bool) *RequestBody {
	content := make(map[string]MediaType)
	content[contentType] = MediaType{
		Schema:  SchemaFrom(data, contentType),
		Example: data,
	}
	return &RequestBody{
		Description: desc,
		Content:     content,
		Required:    required,
	}
}

func (r *RequestBody) ContentBytes() (b []byte, err error) {
	for ct, mt := range r.Content {
		switch ct {
		case ContentTypeJson:
			return json.Marshal(mt.Example)
		case ContentTypeXML:
			return xml.Marshal(mt.Example)
		case ContentTypeOctetStream:
			var ok bool
			if b, ok = mt.Example.([]byte); !ok {
				return nil, fmt.Errorf("failed to cast Example to []byte")
			}
			return b, nil
		default:
			return nil, fmt.Errorf("unknown Content-Type: %s", ct)
		}
	}
	return nil, nil
}

type Responses map[string]Response

type Response struct {
	Description string               `json:"description,omitempty"`
	Headers     map[string]Header    `json:"headers,omitempty"`
	Content     map[string]MediaType `json:"content,omitempty"`
	Links       map[string]Link      `json:"links,omitempty"`
}

type Header struct {
	Description     string  `json:"description,omitempty"`
	Required        bool    `json:"required,omitempty"`
	Deprecated      bool    `json:"deprecated,omitempty"`
	AllowEmptyValue bool    `json:"allowEmptyValue,omitempty"`
	Schema          *Schema `json:"schema,omitempty"`
}

type MediaType struct {
	Schema   *Schema             `json:"schema,omitempty"`
	Example  interface{}         `json:"example,omitempty"`
	Examples map[string]Example  `json:"examples,omitempty"`
	Encoding map[string]Encoding `json:"encoding,omitempty"`
}

type Schema struct {
	Type       string             `json:"type,omitempty"`
	Format     string             `json:"format,omitempty"`
	Properties map[string]*Schema `json:"properties,omitempty"`
	Items      *Schema            `json:"items,omitempty"`
}

func schema(typ, format string) *Schema {
	return &Schema{typ, format, nil, nil}
}

func SchemaFromString(s string) *Schema {
	if _, err := time.Parse(time.RFC3339, s); err == nil {
		return schema("string", "date")
	}
	if _, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return schema("string", "date")
	}
	return schema("string", "")
}

func SchemaFrom(i interface{}, contentType string) (s *Schema) {
	var t reflect.Type
	v := reflect.ValueOf(i)

	if v.IsValid() {
		t = v.Type()
	} else {
		return schema("object", "")
	}

	// Handling base types
	switch v := i.(type) {
	case int8, int16, int32, uint8, uint16, uint32:
		return schema("integer", "int32")
	case int64, int, uint64, uint:
		return schema("integer", "int64")
	case float32:
		return schema("number", "float")
	case float64:
		return schema("number", "double")
	case []byte:
		return schema("string", "binary")
	case time.Time:
		return schema("string", "date")
	case string:
		return SchemaFromString(v)
	case bool:
		return schema("boolean", "")
	}

	switch v.Kind() {
	case reflect.Ptr:
		t = v.Type().Elem()
		return SchemaFrom(reflect.New(t).Elem().Interface(), contentType)
	case reflect.Struct:
		fields := make(map[string]*Schema)
		for i := 0; i < t.NumField(); i++ {
			fieldName := t.Field(i).Name
			if string(fieldName[0]) == strings.ToUpper(string(fieldName[0])) {
				switch contentType {
				case ContentTypeJson, ContentTypeXML:
					tag := "json"
					if contentType == ContentTypeXML {
						tag = "xml"
					}
					tagVal := t.Field(i).Tag.Get(tag)

					// this field should be ignored
					if tagVal == "-" {
						continue
					}

					if tagVal != "" {
						name := strings.SplitN(tagVal, ",", 2)[0]
						fields[name] = SchemaFrom(v.Field(i).Interface(), contentType)
					} else {
						// if there is no json tag we take field name
						fields[fieldName] = SchemaFrom(v.Field(i).Interface(), contentType)
					}
				default:
					panic(fmt.Sprintf("Unkown Content-Type: %s", contentType))
				}
			}
		}
		return &Schema{
			"object", "", fields, nil}
	case reflect.Slice:
		e := t.Elem()
		return &Schema{
			Type:  "array",
			Items: SchemaFrom(reflect.New(e).Interface(), contentType)}
	case reflect.Map:
		// gives the type of the values contained the map
		e := t.Elem()
		return &Schema{
			Type: "object",
			Properties: map[string]*Schema{
				fmt.Sprintf("key(%s)", t.Key()): SchemaFrom(reflect.New(e).Interface(), contentType),
			}}
	}

	return &Schema{
		"object", "", nil, nil}
}

type Link struct {
	OperationRef string                 `json:"operationRef,omitempty"`
	OperationId  string                 `json:"operationId,omitempty"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
	RequestBody  interface{}            `json:"requestBody,omitempty"`
	Description  string                 `json:"description,omitempty"`
	Server       Server                 `json:"server,omitempty"`
}

type Example struct {
	Summary       string      `json:"summary,omitempty"`
	Description   string      `json:"description,omitempty"`
	Value         interface{} `json:"value,omitempty"`
	ExternalValue string      `json:"externalValue,omitempty"`
}

type Encoding struct {
	ContentType   string            `json:"contentType,omitempty"`
	Headers       map[string]Header `json:"headers,omitempty"`
	Style         string            `json:"style,omitempty"`
	Explode       bool              `json:"explode,omitempty"`
	AllowReserved bool              `json:"allowReserved,omitempty"`
}

type SecurityRequirement map[string][]string
