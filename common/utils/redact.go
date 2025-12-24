package utils

// Redact 脱敏字符串，保留前4位和后4位
func Redact(s string) string {
	if s == "" {
		return ""
	}
	length := len(s)
	if length <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[length-4:]
}

// RedactShort 短脱敏，只保留前2位和后2位
func RedactShort(s string) string {
	if s == "" {
		return ""
	}
	length := len(s)
	if length <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[length-2:]
}

// RedactEmail 脱敏邮箱
func RedactEmail(email string) string {
	if email == "" {
		return ""
	}

	// 查找 @ 符号
	atIndex := -1
	for i, c := range email {
		if c == '@' {
			atIndex = i
			break
		}
	}

	if atIndex <= 0 {
		return Redact(email)
	}

	local := email[:atIndex]
	domain := email[atIndex:]

	if len(local) <= 2 {
		return local + "****" + domain
	}

	return local[:2] + "****" + domain
}
