package handlers

func IfEmpty(value string, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}
