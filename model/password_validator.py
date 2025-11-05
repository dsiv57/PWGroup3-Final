import re

class PasswordValidator:
    """
    Classe per validare la forza delle password
    """
    
    @staticmethod
    def validate_strength(password, username=None):
        """
        Valida la forza di una password
        
        Args:
            password (str): Password da validare
            username (str): Username per evitare che sia contenuto nella password (opzionale)
        
        Returns:
            dict: {
                'is_strong': bool,
                'errors': list
            }
        """
        if not password:
            return {
                'is_strong': False,
                'errors': ['Password obbligatoria']
            }
        
        errors = []
        
        if len(password) < 8:
            errors.append('La password deve essere di almeno 8 caratteri')
        
        if not re.search(r'[A-Z]', password):
            errors.append('La password deve contenere almeno una lettera maiuscola')
        
        if not re.search(r'[a-z]', password):
            errors.append('La password deve contenere almeno una lettera minuscola')
        
        if not re.search(r'\d', password):
            errors.append('La password deve contenere almeno un numero')
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;\'`~]', password):
            errors.append('La password deve contenere almeno un carattere speciale (!@#$%^&*)')
        
        if username and username.lower() in password.lower():
            errors.append('La password non deve contenere il tuo username')
        
        return {
            'is_strong': len(errors) == 0,
            'errors': errors
        }
    
    @staticmethod
    def check_requirements(password):
        """
        Controlla singolarmente ogni requisito
        
        Args:
            password (str): Password da controllare
        
        Returns:
            dict: {
                'length': bool,
                'uppercase': bool,
                'lowercase': bool,
                'number': bool,
                'special': bool
            }
        """
        return {
            'length': len(password) >= 8 if password else False,
            'uppercase': bool(re.search(r'[A-Z]', password)) if password else False,
            'lowercase': bool(re.search(r'[a-z]', password)) if password else False,
            'number': bool(re.search(r'\d', password)) if password else False,
            'special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;\'`~]', password)) if password else False
        }