package oauth2

import (
	"fmt"
	"strconv"
)

type ProfileMap map[string]interface{}

// String returns the value for a given key or an empty string if not found
func (u ProfileMap) String(key string) string {
	// json.Unmarshal converts json "null" value to go's "nil", in this case return empty string
	if val, ok := u[key]; ok && val != nil {
		return fmt.Sprintf("%v", val)
	}
	return ""
}

// Bool returns the value for a given key or false if not found.
// It works with values stored as bool or string that can be parsed to bool.
func (u ProfileMap) Bool(key string) bool {
	if val, ok := u[key]; ok && val != nil {
		switch v := val.(type) {
		case bool:
			return v
		case string:
			parsedVal, err := strconv.ParseBool(v)
			if err == nil {
				return parsedVal
			}
		}
	}
	return false
}

type Profile struct {
	ID          string                 `json:"id"`
	CanonicalID string                 `json:"canonical_id"`
	Name        string                 `json:"name"`
	FirstName   string                 `json:"first_name"`
	LastName    string                 `json:"last_name"`
	Email       string                 `json:"email,omitempty"`
	PictureURL  string                 `json:"picture_url"`
	Attributes  map[string]interface{} `json:"attributes,omitempty"`
}

func (u *Profile) SetBoolAttr(key string, val bool) {
	if u.Attributes == nil {
		u.Attributes = map[string]interface{}{}
	}
	u.Attributes[key] = val
}

func (u *Profile) SetStringAttr(key, val string) {
	if u.Attributes == nil {
		u.Attributes = map[string]interface{}{}
	}
	u.Attributes[key] = val
}

func (u *Profile) GetBoolAttr(key string) bool {
	r, ok := u.Attributes[key].(bool)
	if !ok {
		return false
	}
	return r
}

func (u *Profile) GetStringAttr(key string) string {
	r, ok := u.Attributes[key].(string)
	if !ok {
		return ""
	}
	return r
}
