package templates

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"text/template"
)

func Test_NativeTemplates(t *testing.T) {
	type Inventory struct {
		Material string
		Count    uint
	}
	sweaters := Inventory{"wool", 17}
	tmpl, err := template.New("test").Parse("{{.Count}} items are made of {{.Material}}")
	if err != nil {
		panic(err)
	}
	err = tmpl.Execute(os.Stdout, sweaters)
	if err != nil {
		panic(err)
	}
}

func Test_Unmarshal(t *testing.T) {
	type Votes struct {
		OptionA string `json:"option_A"`
	}

	type Data struct {
		Votes *Votes `json:"votes"`
		Count string `json:"count,omitempty"`
	}

	s := `{ "votes": { "option_A": "3" } }`
	data := &Data{
		Votes: &Votes{},
	}
	err := json.Unmarshal([]byte(s), data)
	fmt.Println(err)
	fmt.Println(data.Votes)
}

func Test_Templates(t *testing.T) {
	type Context struct {
		a string
		b int64
	}
	c := Context{
		a: "hello",
		b: 5,
	}
	//fmt.Scanf()
	templ := "{{.a}}"
	data := &Context{}
	res := Fill_(templ, c)
	Parse_(templ, res, data)
}
