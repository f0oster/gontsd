package ace

import (
	"fmt"
)

func ParseACE(data []byte) (GenericACE, int, error) {
	if len(data) < 8 {
		return nil, 0, fmt.Errorf("data too short for ACE header")
	}

	switch data[0] {
	case ACCESS_ALLOWED_ACE_TYPE:
		a, err := parseAccessAllowedACE(data)
		if err != nil {
			return nil, 0, err
		}
		return a, int(a.Size()), nil
	case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
		a, err := parseAccessAllowedObjectACE(data)
		if err != nil {
			return nil, 0, err
		}
		return a, int(a.Size()), nil
	case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
		a, err := parseSystemMandatoryLabelACE(data)
		if err != nil {
			return nil, 0, err
		}
		return a, int(a.Size()), nil
	default:
		return nil, 0, fmt.Errorf("unsupported ACE type: 0x%02X", data[0])
	}
}
