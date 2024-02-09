package utils

func ConvertCString(cString []byte) string {
	for i := 0; i < len(cString); i++ {
		if cString[i] == 0 {
			return string(cString[:i])
		}
	}
	return string(cString)
}
