import re

class InputValidator:
    """
    Classe per validare input utente e rilevare pattern malevoli
    """
    
    SQL_PATTERNS = [
        r"(\bOR\b|\bAND\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
        r"UNION\s+SELECT",
        r"DROP\s+(TABLE|DATABASE|SCHEMA)",
        r"INSERT\s+INTO",
        r"DELETE\s+FROM",
        r"UPDATE\s+\w+\s+SET",
        r"--",
        r";\s*DROP",
        r"';\s*--",
        r"'\s*OR\s*'",
        r"admin'\s*--",
        r"'\s*=\s*'",
        r"1'\s*=\s*'1",
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>",
        r"</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>",
        r"<embed[^>]*>",
        r"<object[^>]*>",
        r"<img[^>]*onerror",
        r"<svg[^>]*onload",
        r"alert\s*\(",
        r"eval\s*\(",
        r"document\.cookie",
        r"window\.location",
    ]
    
    COMMAND_PATTERNS = [
        r";\s*rm\s+-rf",
        r";\s*cat\s+",
        r"\|\s*cat\s+",
        r"&&\s*(rm|del|format)",
        r"`.*`",
        r"\$\(.*\)",
        r">\s*/dev/null",
        r";\s*curl\s+",
        r";\s*wget\s+",
        r"\|\s*nc\s+",
        r";\s*bash",
        r";\s*sh\s+",
    ]
    
    PATH_PATTERNS = [
        r"\.\./",
        r"\.\./\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%2f",
        r"/etc/passwd",
        r"/etc/shadow",
        r"c:\\windows\\system32",
        r"c:/windows/system32",
    ]
    
    @staticmethod
    def validate(input_string, field_name="input"):
        """
        Valida una stringa per rilevare pattern malevoli
        
        Args:
            input_string (str): Stringa da validare
            field_name (str): Nome del campo (per logging)
        
        Returns:
            dict: {
                'is_safe': bool,
                'attack_type': str | None,
                'pattern_matched': str | None,
                'field': str
            }
        """
        if not input_string or not isinstance(input_string, str):
            return {
                'is_safe': True,
                'attack_type': None,
                'pattern_matched': None,
                'field': field_name
            }
        
        input_upper = input_string.upper()
        
        for pattern in InputValidator.SQL_PATTERNS:
            if re.search(pattern, input_upper, re.IGNORECASE):
                return {
                    'is_safe': False,
                    'attack_type': 'SQL_INJECTION',
                    'pattern_matched': pattern,
                    'field': field_name,
                    'input_sample': input_string[:100]
                }
        
        for pattern in InputValidator.XSS_PATTERNS:
            if re.search(pattern, input_string, re.IGNORECASE):
                return {
                    'is_safe': False,
                    'attack_type': 'XSS',
                    'pattern_matched': pattern,
                    'field': field_name,
                    'input_sample': input_string[:100]
                }
        
        for pattern in InputValidator.COMMAND_PATTERNS:
            if re.search(pattern, input_string, re.IGNORECASE):
                return {
                    'is_safe': False,
                    'attack_type': 'COMMAND_INJECTION',
                    'pattern_matched': pattern,
                    'field': field_name,
                    'input_sample': input_string[:100]
                }
        
        for pattern in InputValidator.PATH_PATTERNS:
            if re.search(pattern, input_string, re.IGNORECASE):
                return {
                    'is_safe': False,
                    'attack_type': 'PATH_TRAVERSAL',
                    'pattern_matched': pattern,
                    'field': field_name,
                    'input_sample': input_string[:100]
                }
        
        return {
            'is_safe': True,
            'attack_type': None,
            'pattern_matched': None,
            'field': field_name
        }
    
    @staticmethod
    def validate_sql_only(input_string, field_name="input"):
        """
        Valida SOLO per SQL Injection (per login/register dove XSS/CMD non servono)
        
        Args:
            input_string (str): Stringa da validare
            field_name (str): Nome del campo (per logging)
        
        Returns:
            dict: {
                'is_safe': bool,
                'attack_type': str | None,
                'pattern_matched': str | None,
                'field': str
            }
        """
        if not input_string or not isinstance(input_string, str):
            return {
                'is_safe': True,
                'attack_type': None,
                'pattern_matched': None,
                'field': field_name
            }
        
        input_upper = input_string.upper()
        
        for pattern in InputValidator.SQL_PATTERNS:
            if re.search(pattern, input_upper, re.IGNORECASE):
                return {
                    'is_safe': False,
                    'attack_type': 'SQL_INJECTION',
                    'pattern_matched': pattern,
                    'field': field_name,
                    'input_sample': input_string[:100]
                }
        
        return {
            'is_safe': True,
            'attack_type': None,
            'pattern_matched': None,
            'field': field_name
        }
    
    @staticmethod
    def validate_multiple(fields_dict):
        """
        Valida multipli campi contemporaneamente
        
        Args:
            fields_dict (dict): {'field_name': 'value', ...}
        
        Returns:
            dict: {
                'is_safe': bool,
                'failed_validations': list
            }
        """
        failed = []
        
        for field_name, value in fields_dict.items():
            result = InputValidator.validate(value, field_name)
            if not result['is_safe']:
                failed.append(result)
        
        return {
            'is_safe': len(failed) == 0,
            'failed_validations': failed
        }